package com.google.android.gms.measurement.internal;

import androidx.collection.C0208f;

/* renamed from: com.google.android.gms.measurement.internal.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC3856a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ long c;
    public final /* synthetic */ C3884o d;

    public /* synthetic */ RunnableC3856a(C3884o c3884o, String str, long j, int i) {
        this.a = i;
        this.b = str;
        this.c = j;
        this.d = c3884o;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C3884o c3884o = this.d;
                c3884o.S();
                String str = this.b;
                com.google.android.gms.common.internal.u.e(str);
                C0208f c0208f = c3884o.d;
                boolean zIsEmpty = c0208f.isEmpty();
                long j = this.c;
                if (zIsEmpty) {
                    c3884o.e = j;
                }
                Integer num = (Integer) c0208f.get(str);
                if (num == null) {
                    if (c0208f.c < 100) {
                        c0208f.put(str, 1);
                        c3884o.c.put(str, Long.valueOf(j));
                        break;
                    } else {
                        I i = ((Y) c3884o.b).i;
                        Y.k(i);
                        i.j.f("Too many ads visible");
                        break;
                    }
                } else {
                    c0208f.put(str, Integer.valueOf(num.intValue() + 1));
                    break;
                }
            default:
                C3884o c3884o2 = this.d;
                c3884o2.S();
                String str2 = this.b;
                com.google.android.gms.common.internal.u.e(str2);
                C0208f c0208f2 = c3884o2.d;
                Integer num2 = (Integer) c0208f2.get(str2);
                Y y = (Y) c3884o2.b;
                if (num2 == null) {
                    I i2 = y.i;
                    Y.k(i2);
                    i2.g.g("Call to endAdUnitExposure for unknown ad unit id", str2);
                    break;
                } else {
                    O0 o0 = y.o;
                    Y.j(o0);
                    L0 l0Y = o0.Y(false);
                    int iIntValue = num2.intValue() - 1;
                    if (iIntValue != 0) {
                        c0208f2.put(str2, Integer.valueOf(iIntValue));
                        break;
                    } else {
                        c0208f2.remove(str2);
                        C0208f c0208f3 = c3884o2.c;
                        Long l = (Long) c0208f3.get(str2);
                        long j2 = this.c;
                        I i3 = y.i;
                        if (l == null) {
                            Y.k(i3);
                            i3.g.f("First ad unit exposure time was never set");
                        } else {
                            long jLongValue = j2 - l.longValue();
                            c0208f3.remove(str2);
                            c3884o2.X(str2, jLongValue, l0Y);
                        }
                        if (c0208f2.isEmpty()) {
                            long j3 = c3884o2.e;
                            if (j3 != 0) {
                                c3884o2.W(j2 - j3, l0Y);
                                c3884o2.e = 0L;
                                break;
                            } else {
                                Y.k(i3);
                                i3.g.f("First ad exposure time was never set");
                                break;
                            }
                        }
                    }
                }
                break;
        }
    }
}
