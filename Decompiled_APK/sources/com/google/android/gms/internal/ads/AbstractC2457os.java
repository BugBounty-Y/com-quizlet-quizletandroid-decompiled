package com.google.android.gms.internal.ads;

import android.content.Context;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.tasks.Task;
import java.io.IOException;
import java.io.Serializable;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.os, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2457os {
    public static Boolean a;

    public static int a(int i) {
        return (int) (Integer.rotateLeft((int) (i * (-862048943)), 15) * 461845907);
    }

    public static long b(long j, long j2) {
        long j3 = j + j2;
        if (((j ^ j2) < 0) || ((j ^ j3) >= 0)) {
            return j3;
        }
        throw new ArithmeticException(android.support.v4.media.session.a.g(j2, ")", androidx.compose.animation.d0.t(j, "overflow: checkedAdd(", ", ")));
    }

    public static C2384n4 c(Context context, String str, String str2) {
        C2384n4 c2384n4;
        try {
            c2384n4 = (C2384n4) ((LinkedBlockingQueue) new com.quizlet.remote.model.notes.e(context, str, str2).e).poll(5000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException unused) {
            c2384n4 = null;
        }
        return c2384n4 == null ? com.quizlet.remote.model.notes.e.s() : c2384n4;
    }

    public static Us d(Task task) {
        Us us = new Us();
        us.h = task;
        task.b(Kv.a, new Lr(us, 1));
        return us;
    }

    public static Bt e(Bt bt) {
        return ((bt instanceof Dt) || (bt instanceof Ct)) ? bt : bt instanceof Serializable ? new Ct(bt) : new Dt(bt);
    }

    public static AbstractC2547qw g(byte[] bArr) throws GeneralSecurityException {
        try {
            IA ia = IA.a;
            C2305lB c2305lB = C2305lB.c;
            Gz gzY = Gz.y(bArr, IA.b);
            Xx xx = Xx.b;
            C2604sA c2604sAA = AbstractC2677ty.a(gzY.B());
            C2420ny c2420ny = new C2420ny(gzY, c2604sAA);
            C2634sy c2634sy = (C2634sy) xx.a.get();
            c2634sy.getClass();
            return !c2634sy.d.containsKey(new C2549qy(C2420ny.class, c2604sAA)) ? new Ox(c2420ny) : xx.b(c2420ny);
        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to parse proto", e);
        }
    }

    public static final void j(ByteBuffer byteBuffer, ByteBuffer byteBuffer2, ByteBuffer byteBuffer3, int i) {
        if (i < 0 || byteBuffer2.remaining() < i || byteBuffer3.remaining() < i || byteBuffer.remaining() < i) {
            throw new IllegalArgumentException("That combination of buffers, offsets and length to xor result in out-of-bond accesses.");
        }
        for (int i2 = 0; i2 < i; i2++) {
            byteBuffer.put((byte) (byteBuffer2.get() ^ byteBuffer3.get()));
        }
    }

    public static boolean k(int i, boolean z) {
        int i2 = i & 7;
        if (i2 != 4) {
            return z && i2 == 3;
        }
        return true;
    }

    public static boolean l(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static int m(Object obj) {
        return a(obj == null ? 0 : obj.hashCode());
    }

    public static long n(long j, long j2, RoundingMode roundingMode) {
        roundingMode.getClass();
        long j3 = j / j2;
        long j4 = j - (j2 * j3);
        if (j4 == 0) {
            return j3;
        }
        int i = ((int) ((j ^ j2) >> 63)) | 1;
        switch (AbstractC1854av.a[roundingMode.ordinal()]) {
            case 1:
                AbstractC2543qs.q(false);
                return j3;
            case 2:
                return j3;
            case 3:
                if (i >= 0) {
                    return j3;
                }
                break;
            case 4:
                break;
            case 5:
                if (i <= 0) {
                    return j3;
                }
                break;
            case 6:
            case 7:
            case 8:
                long jAbs = Math.abs(j4);
                long jAbs2 = jAbs - (Math.abs(j2) - jAbs);
                if (jAbs2 == 0) {
                    if (roundingMode != RoundingMode.HALF_UP && (roundingMode != RoundingMode.HALF_EVEN || (1 & j3) == 0)) {
                        return j3;
                    }
                } else if (jAbs2 <= 0) {
                    return j3;
                }
                break;
            default:
                throw new AssertionError();
        }
        return j3 + i;
    }

    public static AbstractC2457os o(Class cls) {
        return System.getProperty("java.vm.name").equalsIgnoreCase("Dalvik") ? new C2735vC(cls.getSimpleName(), 0) : new C2735vC(cls.getSimpleName(), 1);
    }

    public static void q(int i, Object[] objArr) {
        for (int i2 = 0; i2 < i; i2++) {
            if (objArr[i2] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i2, "at index "));
            }
        }
    }

    public static byte[] r(byte[]... bArr) throws GeneralSecurityException {
        int i = 0;
        int i2 = 0;
        while (true) {
            if (i >= bArr.length) {
                byte[] bArr2 = new byte[i2];
                int i3 = 0;
                for (byte[] bArr3 : bArr) {
                    int length = bArr3.length;
                    System.arraycopy(bArr3, 0, bArr2, i3, length);
                    i3 += length;
                }
                return bArr2;
            }
            int length2 = bArr[i].length;
            if (i2 > SubsamplingScaleImageView.TILE_SIZE_AUTO - length2) {
                throw new GeneralSecurityException("exceeded size limit");
            }
            i2 += length2;
            i++;
        }
    }

    public static long s(long j, long j2) {
        AbstractC2543qs.h(j, "a");
        AbstractC2543qs.h(j2, "b");
        if (j == 0) {
            return j2;
        }
        if (j2 == 0) {
            return j;
        }
        int iNumberOfTrailingZeros = Long.numberOfTrailingZeros(j);
        long jNumberOfTrailingZeros = j >> iNumberOfTrailingZeros;
        int iNumberOfTrailingZeros2 = Long.numberOfTrailingZeros(j2);
        long j3 = j2 >> iNumberOfTrailingZeros2;
        while (jNumberOfTrailingZeros != j3) {
            long j4 = jNumberOfTrailingZeros - j3;
            long j5 = (j4 >> 63) & j4;
            long j6 = (j4 - j5) - j5;
            jNumberOfTrailingZeros = j6 >> Long.numberOfTrailingZeros(j6);
            j3 += j5;
        }
        return jNumberOfTrailingZeros << Math.min(iNumberOfTrailingZeros, iNumberOfTrailingZeros2);
    }

    public static final byte[] u(int i, byte[] bArr, byte[] bArr2) {
        if (bArr.length - 16 < i) {
            throw new IllegalArgumentException("That combination of buffers, offsets and length to xor result in out-of-bond accesses.");
        }
        byte[] bArr3 = new byte[16];
        for (int i2 = 0; i2 < 16; i2++) {
            bArr3[i2] = (byte) (bArr[i2 + i] ^ bArr2[i2]);
        }
        return bArr3;
    }

    public static long v(long j, long j2) {
        int iNumberOfLeadingZeros = Long.numberOfLeadingZeros(~j2) + Long.numberOfLeadingZeros(j2) + Long.numberOfLeadingZeros(~j) + Long.numberOfLeadingZeros(j);
        if (iNumberOfLeadingZeros > 65) {
            return j * j2;
        }
        long j3 = j ^ j2;
        long j4 = (j3 >>> 63) + Long.MAX_VALUE;
        if (!((iNumberOfLeadingZeros < 64) | ((j2 == Long.MIN_VALUE) & (j < 0)))) {
            long j5 = j * j2;
            if (j == 0 || j5 / j == j2) {
                return j5;
            }
        }
        return j4;
    }

    public static Executor w(final Executor executor, final Mv mv) {
        executor.getClass();
        return executor == Kv.a ? executor : new Executor() { // from class: com.google.android.gms.internal.ads.Zv
            @Override // java.util.concurrent.Executor
            public final void execute(Runnable runnable) {
                try {
                    executor.execute(runnable);
                } catch (RejectedExecutionException e) {
                    mv.h(e);
                }
            }
        };
    }

    public abstract boolean A(AbstractC2674tv abstractC2674tv, C2631sv c2631sv, C2631sv c2631sv2);

    public abstract C2331lv f(AbstractC2460ov abstractC2460ov);

    public abstract void h(int i, byte[] bArr, int i2);

    public abstract void i(String str);

    public abstract C2631sv p(AbstractC2460ov abstractC2460ov);

    public abstract void t(C2631sv c2631sv, C2631sv c2631sv2);

    public abstract void x(C2631sv c2631sv, Thread thread);

    public abstract boolean y(AbstractC2460ov abstractC2460ov, C2331lv c2331lv, C2331lv c2331lv2);

    public abstract boolean z(AbstractC2674tv abstractC2674tv, Object obj, Object obj2);
}
