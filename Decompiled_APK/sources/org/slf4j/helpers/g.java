package org.slf4j.helpers;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.PrintStream;

/* loaded from: classes3.dex */
public abstract class g {
    public static final int a;
    public static final int b;

    static {
        int i;
        String[] strArr = {"System.out", "stdout", "sysout"};
        String property = System.getProperty("slf4j.internal.report.stream");
        int i2 = 2;
        if (property == null || property.isEmpty()) {
            i = 1;
        } else {
            for (int i3 = 0; i3 < 3; i3++) {
                if (strArr[i3].equalsIgnoreCase(property)) {
                    i = 2;
                    break;
                }
            }
            i = 1;
        }
        a = i;
        String property2 = System.getProperty("slf4j.internal.verbosity");
        if (property2 != null && !property2.isEmpty()) {
            if (property2.equalsIgnoreCase("DEBUG")) {
                i2 = 1;
            } else if (property2.equalsIgnoreCase("ERROR")) {
                i2 = 4;
            } else if (property2.equalsIgnoreCase("WARN")) {
                i2 = 3;
            }
        }
        b = i2;
    }

    public static final void a(String str, Throwable th) {
        b().println("SLF4J(E): " + str);
        b().println("SLF4J(E): Reported exception:");
        th.printStackTrace(b());
    }

    public static PrintStream b() {
        return AbstractC0147y.k(a) != 1 ? System.err : System.out;
    }

    public static final void c(String str) {
        if (AbstractC0147y.k(3) >= AbstractC0147y.k(b)) {
            b().println("SLF4J(W): " + str);
        }
    }
}
