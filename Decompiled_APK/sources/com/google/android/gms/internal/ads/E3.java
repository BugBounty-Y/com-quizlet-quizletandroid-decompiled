package com.google.android.gms.internal.ads;

import java.util.HashSet;

/* loaded from: classes2.dex */
public abstract class E3 {
    public static final HashSet a = new HashSet();
    public static String b = "media3.common";

    public static synchronized void a(String str) {
        if (a.add(str)) {
            b = b + ", " + str;
        }
    }
}
