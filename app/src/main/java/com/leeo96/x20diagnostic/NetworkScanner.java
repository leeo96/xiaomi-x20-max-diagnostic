package com.leeo96.x20diagnostic;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Discovers MiIO devices on the active local IPv4 network without a token. */
public final class NetworkScanner {
    private static final int PORT = 54321;
    private static final byte[] HELLO = buildHello();

    private NetworkScanner() {}

    public static JSONObject scan(Context context) throws Exception {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) throw new IllegalStateException("Serviço de rede indisponível");
        Network network = cm.getActiveNetwork();
        if (network == null) throw new IllegalStateException("Nenhuma rede ativa");
        LinkProperties lp = cm.getLinkProperties(network);
        if (lp == null) throw new IllegalStateException("Não foi possível obter os dados da rede local");

        Inet4Address local = null;
        int prefix = 24;
        for (LinkAddress la : lp.getLinkAddresses()) {
            if (la.getAddress() instanceof Inet4Address && !la.getAddress().isLoopbackAddress()) {
                local = (Inet4Address) la.getAddress();
                prefix = la.getPrefixLength();
                break;
            }
        }
        if (local == null) throw new IllegalStateException("Nenhum endereço IPv4 local encontrado. Conecte o celular ao Wi‑Fi do robô.");

        // Keep the sweep bounded on unusual home/VPN networks. /23 scans 510 hosts;
        // anything larger falls back to the local /24, which covers most home Wi‑Fi setups.
        int effectivePrefix = prefix;
        if (effectivePrefix < 23 || effectivePrefix > 30) effectivePrefix = 24;

        long localInt = ipv4ToLong(local.getAddress());
        long mask = (0xFFFFFFFFL << (32 - effectivePrefix)) & 0xFFFFFFFFL;
        long networkInt = localInt & mask;
        long broadcastInt = networkInt | (~mask & 0xFFFFFFFFL);
        long first = networkInt + 1;
        long last = broadcastInt - 1;

        JSONArray devices = new JSONArray();
        Set<String> seen = new HashSet<>();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setBroadcast(true);
            socket.setSoTimeout(180);

            // Directed broadcast first; some devices answer immediately.
            try {
                InetAddress broadcast = InetAddress.getByAddress(longToIpv4(broadcastInt));
                socket.send(new DatagramPacket(HELLO, HELLO.length, broadcast, PORT));
            } catch (Exception ignored) {}

            // Fast unicast sweep. Sending is cheap; all replies come back to the same socket.
            for (long candidate = first; candidate <= last; candidate++) {
                if (candidate == localInt) continue;
                InetAddress target = InetAddress.getByAddress(longToIpv4(candidate));
                try {
                    socket.send(new DatagramPacket(HELLO, HELLO.length, target, PORT));
                } catch (Exception ignored) {}
            }

            long deadline = System.currentTimeMillis() + 2600L;
            byte[] buffer = new byte[1024];
            while (System.currentTimeMillis() < deadline) {
                DatagramPacket rx = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(rx);
                } catch (SocketTimeoutException timeout) {
                    continue;
                }
                byte[] data = Arrays.copyOf(rx.getData(), rx.getLength());
                if (data.length < 32 || (data[0] & 0xFF) != 0x21 || (data[1] & 0xFF) != 0x31) continue;
                String ip = rx.getAddress().getHostAddress();
                if (!seen.add(ip)) continue;

                JSONObject d = new JSONObject();
                d.put("ip", ip);
                d.put("deviceId", Long.toUnsignedString(readUInt32(data, 8)));
                d.put("stamp", readUInt32(data, 12));
                devices.put(d);
            }
        }

        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("localIp", local.getHostAddress());
        out.put("prefixLength", prefix);
        out.put("effectivePrefixLength", effectivePrefix);
        out.put("hostCount", Math.max(0, last - first + 1));
        out.put("devices", devices);
        return out;
    }

    private static long ipv4ToLong(byte[] b) {
        return ((long) (b[0] & 0xFF) << 24)
                | ((long) (b[1] & 0xFF) << 16)
                | ((long) (b[2] & 0xFF) << 8)
                | (long) (b[3] & 0xFF);
    }

    private static byte[] longToIpv4(long v) {
        return new byte[] {
                (byte) ((v >>> 24) & 0xFF),
                (byte) ((v >>> 16) & 0xFF),
                (byte) ((v >>> 8) & 0xFF),
                (byte) (v & 0xFF)
        };
    }

    private static long readUInt32(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (long) (data[offset + 3] & 0xFF);
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
}
