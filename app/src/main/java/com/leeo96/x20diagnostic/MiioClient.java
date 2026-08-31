package com.leeo96.x20diagnostic;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal, read-only implementation of Xiaomi's MiIO LAN protocol.
 *
 * It only sends the MIoT method "get_properties". There is deliberately no
 * implementation for set_properties or actions in this diagnostic app.
 */
public final class MiioClient {
    public static final int PORT = 54321;
    private static final int TIMEOUT_MS = 4500;
    private static final int MAX_PROPERTIES_PER_REQUEST = 12;
    private static final byte[] HELLO = buildHello();

    private final byte[] token;
    private final AtomicInteger requestId = new AtomicInteger(1);

    public static final class Property {
        public final int siid;
        public final int piid;
        public final String name;

        public Property(int siid, int piid, String name) {
            this.siid = siid;
            this.piid = piid;
            this.name = name == null ? (siid + "/" + piid) : name;
        }
    }

    private static final class HelloInfo {
        final long deviceId;
        final long stamp;
        final long receivedAtMs;

        HelloInfo(long deviceId, long stamp, long receivedAtMs) {
            this.deviceId = deviceId;
            this.stamp = stamp;
            this.receivedAtMs = receivedAtMs;
        }

        long currentStamp() {
            long elapsed = Math.max(0, (System.currentTimeMillis() - receivedAtMs) / 1000L);
            return (stamp + elapsed) & 0xFFFFFFFFL;
        }
    }

    public MiioClient(String tokenHex) {
        if (tokenHex == null) throw new IllegalArgumentException("Token ausente");
        String clean = tokenHex.trim().replace(" ", "");
        if (!clean.matches("(?i)[0-9a-f]{32}")) {
            throw new IllegalArgumentException("O token MiIO deve ter exatamente 32 caracteres hexadecimais");
        }
        this.token = hexToBytes(clean);
    }

    public JSONObject readProperties(String ip, List<Property> properties) throws Exception {
        if (ip == null || ip.trim().isEmpty()) throw new IllegalArgumentException("IP ausente");
        if (properties == null || properties.isEmpty()) throw new IllegalArgumentException("Nenhuma propriedade solicitada");

        InetAddress address = InetAddress.getByName(ip.trim());
        HelloInfo hello = hello(address);

        JSONArray combined = new JSONArray();
        JSONArray rawResponses = new JSONArray();

        for (int offset = 0; offset < properties.size(); offset += MAX_PROPERTIES_PER_REQUEST) {
            int end = Math.min(properties.size(), offset + MAX_PROPERTIES_PER_REQUEST);
            List<Property> batch = properties.subList(offset, end);

            JSONArray params = new JSONArray();
            for (Property p : batch) {
                JSONObject item = new JSONObject();
                item.put("did", p.siid + "-" + p.piid);
                item.put("siid", p.siid);
                item.put("piid", p.piid);
                params.put(item);
            }

            JSONObject payload = new JSONObject();
            payload.put("id", requestId.getAndIncrement());
            payload.put("method", "get_properties");
            payload.put("params", params);

            byte[] outgoing = buildPacket(
                    hello.deviceId,
                    hello.currentStamp(),
                    token,
                    payload.toString().getBytes(StandardCharsets.UTF_8)
            );
            byte[] incoming = sendReceive(address, outgoing);
            JSONObject response = parseResponse(incoming, token);
            rawResponses.put(response);

            JSONArray result = response.optJSONArray("result");
            if (result != null) {
                for (int i = 0; i < result.length(); i++) {
                    JSONObject r = result.optJSONObject(i);
                    if (r == null) continue;
                    JSONObject enriched = new JSONObject(r.toString());
                    int siid = enriched.optInt("siid", -1);
                    int piid = enriched.optInt("piid", -1);
                    for (Property p : batch) {
                        if (p.siid == siid && p.piid == piid) {
                            enriched.put("name", p.name);
                            break;
                        }
                    }
                    combined.put(enriched);
                }
            }

            if (response.has("error")) {
                JSONObject err = new JSONObject();
                err.put("code", -99999);
                err.put("did", "batch-" + offset);
                err.put("name", "Resposta MIoT");
                err.put("value", response.get("error"));
                combined.put(err);
            }
        }

        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("ip", ip.trim());
        out.put("deviceId", Long.toUnsignedString(hello.deviceId));
        out.put("helloStamp", hello.stamp);
        out.put("results", combined);
        out.put("rawResponses", rawResponses);
        return out;
    }

    public JSONObject helloOnly(String ip) throws Exception {
        InetAddress address = InetAddress.getByName(ip.trim());
        HelloInfo hello = hello(address);
        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("ip", ip.trim());
        out.put("deviceId", Long.toUnsignedString(hello.deviceId));
        out.put("stamp", hello.stamp);
        return out;
    }

    private HelloInfo hello(InetAddress address) throws Exception {
        byte[] response = sendReceive(address, HELLO);
        if (response.length < 32) throw new IllegalStateException("Resposta MiIO hello curta: " + response.length + " bytes");
        if ((response[0] & 0xFF) != 0x21 || (response[1] & 0xFF) != 0x31) {
            throw new IllegalStateException("Resposta não parece ser MiIO (magic inválido)");
        }
        long deviceId = readUInt32(response, 8);
        long stamp = readUInt32(response, 12);
        return new HelloInfo(deviceId, stamp, System.currentTimeMillis());
    }

    private static byte[] sendReceive(InetAddress address, byte[] payload) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(TIMEOUT_MS);
            DatagramPacket tx = new DatagramPacket(payload, payload.length, address, PORT);
            socket.send(tx);

            byte[] buffer = new byte[65535];
            DatagramPacket rx = new DatagramPacket(buffer, buffer.length);
            socket.receive(rx);
            return Arrays.copyOf(rx.getData(), rx.getLength());
        }
    }

    private static byte[] buildPacket(long deviceId, long stamp, byte[] token, byte[] plainPayload) throws Exception {
        byte[] encrypted = encrypt(plainPayload, token);
        int totalLength = 32 + encrypted.length;
        byte[] packet = new byte[totalLength];

        packet[0] = 0x21;
        packet[1] = 0x31;
        packet[2] = (byte) ((totalLength >>> 8) & 0xFF);
        packet[3] = (byte) (totalLength & 0xFF);
        // bytes 4..7 remain zero
        writeUInt32(packet, 8, deviceId);
        writeUInt32(packet, 12, stamp);

        // MiIO checksum is MD5(header[0..15] + token + encrypted payload).
        System.arraycopy(token, 0, packet, 16, 16);
        System.arraycopy(encrypted, 0, packet, 32, encrypted.length);
        byte[] checksum = md5(packet);
        System.arraycopy(checksum, 0, packet, 16, 16);
        return packet;
    }

    private static JSONObject parseResponse(byte[] packet, byte[] token) throws Exception {
        if (packet.length < 32) throw new IllegalStateException("Resposta MiIO inválida: " + packet.length + " bytes");
        if ((packet[0] & 0xFF) != 0x21 || (packet[1] & 0xFF) != 0x31) {
            throw new IllegalStateException("Magic MiIO inválido na resposta");
        }

        int declaredLength = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
        if (declaredLength > packet.length || declaredLength < 32) {
            throw new IllegalStateException("Comprimento MiIO inválido: " + declaredLength + "/" + packet.length);
        }
        if (declaredLength == 32) {
            JSONObject empty = new JSONObject();
            empty.put("error", "Resposta sem payload");
            return empty;
        }

        byte[] encrypted = Arrays.copyOfRange(packet, 32, declaredLength);
        byte[] plain = decrypt(encrypted, token);
        String text = new String(plain, StandardCharsets.UTF_8).replace("\u0000", "").trim();
        return new JSONObject(text);
    }

    private static byte[] encrypt(byte[] plain, byte[] token) throws Exception {
        byte[] key = md5(token);
        ByteArrayOutputStream ivInput = new ByteArrayOutputStream();
        ivInput.write(key);
        ivInput.write(token);
        byte[] iv = md5(ivInput.toByteArray());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(plain);
    }

    private static byte[] decrypt(byte[] encrypted, byte[] token) throws Exception {
        byte[] key = md5(token);
        ByteArrayOutputStream ivInput = new ByteArrayOutputStream();
        ivInput.write(key);
        ivInput.write(token);
        byte[] iv = md5(ivInput.toByteArray());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    private static byte[] md5(byte[] input) throws Exception {
        return MessageDigest.getInstance("MD5").digest(input);
    }

    private static long readUInt32(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (long) (data[offset + 3] & 0xFF);
    }

    private static void writeUInt32(byte[] data, int offset, long value) {
        data[offset] = (byte) ((value >>> 24) & 0xFF);
        data[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        data[offset + 2] = (byte) ((value >>> 8) & 0xFF);
        data[offset + 3] = (byte) (value & 0xFF);
    }

    private static byte[] buildHello() {
        byte[] hello = new byte[32];
        hello[0] = 0x21;
        hello[1] = 0x31;
        hello[2] = 0x00;
        hello[3] = 0x20;
        Arrays.fill(hello, 4, 32, (byte) 0xFF);
        return hello;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static List<Property> parsePropertyList(String json) throws Exception {
        JSONArray arr = new JSONArray(json);
        List<Property> out = new ArrayList<>();
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            int siid = o.getInt("siid");
            int piid = o.getInt("piid");
            String name = o.optString("name", siid + "/" + piid);
            out.add(new Property(siid, piid, name));
        }
        return out;
    }
}
