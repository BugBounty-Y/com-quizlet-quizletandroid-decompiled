package com.google.gson.internal.sql;

import com.google.gson.internal.bind.e;
import java.sql.Date;
import java.sql.Timestamp;

/* loaded from: classes2.dex */
public abstract class b {
    public static final boolean a;
    public static final com.google.gson.internal.bind.a b;
    public static final com.google.gson.internal.bind.a c;
    public static final com.google.gson.internal.bind.a d;

    static {
        boolean z;
        try {
            Class.forName("java.sql.Date");
            z = true;
        } catch (ClassNotFoundException unused) {
            z = false;
        }
        a = z;
        if (!z) {
            b = null;
            c = null;
            d = null;
        } else {
            new e(Date.class);
            new e(Timestamp.class);
            b = a.c;
            c = a.d;
            d = a.e;
        }
    }
}
