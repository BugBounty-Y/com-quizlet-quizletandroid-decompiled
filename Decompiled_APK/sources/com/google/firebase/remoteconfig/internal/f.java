package com.google.firebase.remoteconfig.internal;

import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class f {
    public static final Pattern e;
    public static final Pattern f;
    public final HashSet a = new HashSet();
    public final Executor b;
    public final b c;
    public final b d;

    static {
        Charset.forName("UTF-8");
        e = Pattern.compile("^(1|true|t|yes|y|on)$", 2);
        f = Pattern.compile("^(0|false|f|no|n|off|)$", 2);
    }

    public f(Executor executor, b bVar, b bVar2) {
        this.b = executor;
        this.c = bVar;
        this.d = bVar2;
    }

    public static HashSet a(b bVar) {
        HashSet hashSet = new HashSet();
        c cVarC = bVar.c();
        if (cVarC != null) {
            Iterator<String> itKeys = cVarC.b.keys();
            while (itKeys.hasNext()) {
                hashSet.add(itKeys.next());
            }
        }
        return hashSet;
    }
}
