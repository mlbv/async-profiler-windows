/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.wall;

import java.io.InputStream;
import java.net.Socket;

class BusyClient extends Thread {
    private final int port;

    BusyClient(int port) {
        this.port = port;
    }

    @Override
    public void run() {
        try {
            byte[] buf = new byte[4096];

            Socket s = new Socket(SocketTest.HOST, port);

            InputStream in = s.getInputStream();
            while (in.read(buf) >= 0) {
                // keep reading
            }
            System.out.println(Thread.currentThread().getName() + " stopped");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
