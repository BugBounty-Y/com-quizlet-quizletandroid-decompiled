package com.google.firebase.perf.transport;

import android.content.Context;
import androidx.camera.camera2.internal.C0148z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3692p;
import com.google.firebase.perf.v1.A;
import com.google.firebase.perf.v1.z;
import com.google.protobuf.B;
import java.util.Random;

/* loaded from: classes2.dex */
public final class d {
    public final com.google.firebase.perf.config.a a;
    public final double b;
    public final double c;
    public final c d;
    public final c e;

    public d(Context context, C0148z c0148z) {
        assistantMode.utils.studiableMetadata.b bVar = new assistantMode.utils.studiableMetadata.b(19);
        double dNextDouble = new Random().nextDouble();
        double dNextDouble2 = new Random().nextDouble();
        com.google.firebase.perf.config.a aVarE = com.google.firebase.perf.config.a.e();
        this.d = null;
        this.e = null;
        boolean z = false;
        if (!(0.0d <= dNextDouble && dNextDouble < 1.0d)) {
            throw new IllegalArgumentException("Sampling bucket ID should be in range [0.0, 1.0).");
        }
        if (0.0d <= dNextDouble2 && dNextDouble2 < 1.0d) {
            z = true;
        }
        if (!z) {
            throw new IllegalArgumentException("Fragment sampling bucket ID should be in range [0.0, 1.0).");
        }
        this.b = dNextDouble;
        this.c = dNextDouble2;
        this.a = aVarE;
        this.d = new c(c0148z, bVar, aVarE, "Trace");
        this.e = new c(c0148z, bVar, aVarE, "Network");
        AbstractC3692p.a(context);
    }

    public static boolean a(B b) {
        return b.size() > 0 && ((z) b.get(0)).z() > 0 && ((z) b.get(0)).y() == A.GAUGES_AND_SYSTEM_EVENTS;
    }
}
