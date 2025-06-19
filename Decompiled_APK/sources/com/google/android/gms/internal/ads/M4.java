package com.google.android.gms.internal.ads;

import android.os.ConditionVariable;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Random;

/* loaded from: classes2.dex */
public final class M4 {
    public static final ConditionVariable c = new ConditionVariable();
    public static volatile Ds d = null;
    public static volatile Random e = null;
    public final Z4 a;
    public volatile Boolean b;

    public M4(Z4 z4) {
        this.a = z4;
        z4.b.execute(new RunnableC1989e(this, 3));
    }

    public final void a(int i, int i2, long j, String str, Exception exc) {
        try {
            c.block();
            if (!this.b.booleanValue() || d == null) {
                return;
            }
            V3 v3W = Y3.w();
            String packageName = this.a.a.getPackageName();
            v3W.e();
            Y3.x((Y3) v3W.b, packageName);
            v3W.e();
            Y3.B((Y3) v3W.b, j);
            if (str != null) {
                v3W.e();
                Y3.y((Y3) v3W.b, str);
            }
            if (exc != null) {
                StringWriter stringWriter = new StringWriter();
                exc.printStackTrace(new PrintWriter(stringWriter));
                String string = stringWriter.toString();
                v3W.e();
                Y3.C((Y3) v3W.b, string);
                String name = exc.getClass().getName();
                v3W.e();
                Y3.A((Y3) v3W.b, name);
            }
            Ds ds = d;
            byte[] bArrD = ((Y3) v3W.c()).d();
            ds.getClass();
            androidx.compose.ui.text.android.selection.f fVar = new androidx.compose.ui.text.android.selection.f(ds, bArrD);
            fVar.c = i;
            if (i2 != -1) {
                fVar.b = i2;
            }
            fVar.r();
        } catch (Exception unused) {
        }
    }
}
