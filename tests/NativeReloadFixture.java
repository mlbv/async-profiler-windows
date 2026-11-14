/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

public final class NativeReloadFixture {
    private static native long[] load(String path);
    private static native boolean unload();
    private static native boolean present();
    private static native long run(int count);
    private static native long timed(int milliseconds);
    private static native void threadAttach();

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            if (command.startsWith("load ")) System.out.println("LOADED " + Arrays.toString(load(command.substring(5))));
            else if (command.equals("unload")) System.out.println("PRESENT " + unload());
            else if (command.equals("present")) System.out.println("PRESENT " + present());
            else if (command.equals("thread")) { threadAttach(); System.out.println("THREAD_OK"); }
            else if (command.startsWith("timed ")) System.out.println("TIMED " + timed(Integer.parseInt(command.substring(6))));
            else System.out.println("RESULT " + run(Integer.parseInt(command)));
        }
    }
}
