package com.google.android.gms.internal.ads;

import android.content.Context;
import android.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.h5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2127h5 extends AbstractCallableC2599s5 {
    public static final Os i = new Os(6);
    public final Context h;

    public C2127h5(Z4 z4, C1864b4 c1864b4, int i2, Context context) {
        super(z4, "agDdf5wrmtJ0cP5XVK0JCsJ4BViR17o/n9P6hmH0muvYwmpx2DZ552/tAJvOo6qR", "48yXjRp5G93PEoVZx8WBMAeqgOhil0yQSUdmW98nZyI=", c1864b4, i2, 29);
        this.h = context;
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        C1864b4 c1864b4 = this.d;
        c1864b4.e();
        C2384n4.B0((C2384n4) c1864b4.b, "E");
        Context context = this.h;
        AtomicReference atomicReferenceG = i.g(context.getPackageName());
        if (atomicReferenceG.get() == null) {
            synchronized (atomicReferenceG) {
                try {
                    if (atomicReferenceG.get() == null) {
                        atomicReferenceG.set((String) this.e.invoke(null, context));
                    }
                } finally {
                }
            }
        }
        String str = (String) atomicReferenceG.get();
        C1864b4 c1864b42 = this.d;
        synchronized (c1864b42) {
            String strEncodeToString = Base64.encodeToString(str.getBytes(), 11);
            c1864b42.e();
            C2384n4.B0((C2384n4) c1864b42.b, strEncodeToString);
        }
    }
}
