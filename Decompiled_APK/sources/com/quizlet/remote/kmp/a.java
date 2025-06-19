package com.quizlet.remote.kmp;

import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.H;
import okhttp3.J;

/* loaded from: classes3.dex */
public final class a {
    public final A a;

    public a(A delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.a = delegate;
    }

    public static final com.quizlet.shared.httpclient.b a(a aVar, H h) {
        String strF;
        aVar.getClass();
        J j = h.g;
        if (j != null) {
            try {
                strF = j.f();
                j.close();
            } finally {
            }
        } else {
            strF = null;
        }
        return new com.quizlet.shared.httpclient.b(strF, h.d, h.c);
    }
}
