package androidx.camera.core.impl;

import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.SystemClock;
import android.text.Spanned;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.InitializationException;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1971dh;
import com.google.android.gms.internal.ads.AbstractC2330lu;
import com.google.android.gms.internal.ads.C1862b2;
import com.google.android.gms.internal.ads.C2244ju;
import com.google.android.gms.internal.ads.C2446oh;
import com.google.android.gms.internal.ads.C2918zh;
import com.google.android.gms.internal.ads.Gg;
import com.google.android.gms.internal.ads.InterfaceC2380n0;
import com.google.android.gms.internal.ads.InterfaceC2491pj;
import com.google.android.gms.internal.ads.Kh;
import com.google.android.gms.internal.ads.Kn;
import com.google.android.gms.internal.ads.Pk;
import com.google.android.gms.internal.ads.RD;
import com.google.android.gms.internal.ads.SD;
import com.google.android.gms.internal.ads.Sh;
import com.google.android.gms.internal.ads.X1;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.util.ArrayList;

/* renamed from: androidx.camera.core.impl.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0186z implements InterfaceC2491pj, Pk {
    public final /* synthetic */ int a = 4;
    public int b;
    public long c;
    public Object d;

    public /* synthetic */ C0186z() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.InterfaceC2491pj, com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        int i;
        switch (this.a) {
            case 2:
                X1 x1 = (X1) obj;
                C1862b2 c1862b2 = (C1862b2) this.d;
                AbstractC1795We.p(c1862b2.h);
                AbstractC2330lu abstractC2330lu = x1.a;
                ArrayList<? extends Parcelable> arrayList = new ArrayList<>(abstractC2330lu.size());
                int i2 = 0;
                C2244ju c2244juListIterator = abstractC2330lu.listIterator(0);
                while (c2244juListIterator.hasNext()) {
                    Gg gg = (Gg) c2244juListIterator.next();
                    gg.getClass();
                    Bundle bundle = new Bundle();
                    CharSequence charSequence = gg.a;
                    if (charSequence != null) {
                        bundle.putCharSequence(Gg.p, charSequence);
                        if (charSequence instanceof Spanned) {
                            Spanned spanned = (Spanned) charSequence;
                            String str = AbstractC1971dh.a;
                            ArrayList<? extends Parcelable> arrayList2 = new ArrayList<>();
                            C2918zh[] c2918zhArr = (C2918zh[]) spanned.getSpans(i2, spanned.length(), C2918zh.class);
                            int length = c2918zhArr.length;
                            for (int i3 = i2; i3 < length; i3++) {
                                C2918zh c2918zh = c2918zhArr[i3];
                                c2918zh.getClass();
                                Bundle bundle2 = new Bundle();
                                bundle2.putString(C2918zh.c, c2918zh.a);
                                bundle2.putInt(C2918zh.d, c2918zh.b);
                                arrayList2.add(AbstractC1971dh.a(spanned, c2918zh, 1, bundle2));
                            }
                            for (Kh kh : (Kh[]) spanned.getSpans(0, spanned.length(), Kh.class)) {
                                kh.getClass();
                                Bundle bundle3 = new Bundle();
                                bundle3.putInt(Kh.d, kh.a);
                                bundle3.putInt(Kh.e, kh.b);
                                bundle3.putInt(Kh.f, kh.c);
                                arrayList2.add(AbstractC1971dh.a(spanned, kh, 2, bundle3));
                            }
                            for (C2446oh c2446oh : (C2446oh[]) spanned.getSpans(0, spanned.length(), C2446oh.class)) {
                                arrayList2.add(AbstractC1971dh.a(spanned, c2446oh, 3, null));
                            }
                            for (Sh sh : (Sh[]) spanned.getSpans(0, spanned.length(), Sh.class)) {
                                sh.getClass();
                                Bundle bundle4 = new Bundle();
                                bundle4.putString(Sh.b, sh.a);
                                arrayList2.add(AbstractC1971dh.a(spanned, sh, 4, bundle4));
                            }
                            if (!arrayList2.isEmpty()) {
                                bundle.putParcelableArrayList(Gg.q, arrayList2);
                            }
                        }
                    }
                    bundle.putSerializable(Gg.r, gg.b);
                    bundle.putSerializable(Gg.s, gg.c);
                    bundle.putFloat(Gg.u, gg.e);
                    bundle.putInt(Gg.v, gg.f);
                    bundle.putInt(Gg.w, gg.g);
                    bundle.putFloat(Gg.x, gg.h);
                    bundle.putInt(Gg.y, gg.i);
                    bundle.putInt(Gg.z, gg.l);
                    bundle.putFloat(Gg.A, gg.m);
                    bundle.putFloat(Gg.B, gg.j);
                    bundle.putFloat(Gg.C, gg.k);
                    bundle.putBoolean(Gg.E, false);
                    bundle.putInt(Gg.D, -16777216);
                    bundle.putInt(Gg.F, gg.n);
                    bundle.putFloat(Gg.G, gg.o);
                    Bitmap bitmap = gg.d;
                    if (bitmap != null) {
                        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                        i = 0;
                        AbstractC1795We.L(bitmap.compress(Bitmap.CompressFormat.PNG, 0, byteArrayOutputStream));
                        bundle.putByteArray(Gg.t, byteArrayOutputStream.toByteArray());
                    } else {
                        i = 0;
                    }
                    arrayList.add(bundle);
                    i2 = i;
                }
                boolean z = i2;
                Bundle bundle5 = new Bundle();
                bundle5.putParcelableArrayList("c", arrayList);
                bundle5.putLong("d", x1.c);
                Parcel parcelObtain = Parcel.obtain();
                parcelObtain.writeBundle(bundle5);
                byte[] bArrMarshall = parcelObtain.marshall();
                parcelObtain.recycle();
                int length2 = bArrMarshall.length;
                Kn kn = c1862b2.c;
                kn.h(length2, bArrMarshall);
                InterfaceC2380n0 interfaceC2380n0 = c1862b2.a;
                interfaceC2380n0.e(length2, kn);
                long j = x1.b;
                long j2 = this.c;
                if (j == -9223372036854775807L) {
                    if (c1862b2.h.r == Long.MAX_VALUE) {
                        z = 1;
                    }
                    AbstractC1795We.L(z);
                } else {
                    long j3 = c1862b2.h.r;
                    j2 = j3 == Long.MAX_VALUE ? j2 + j : j + j3;
                }
                interfaceC2380n0.f(j2, this.b | 1, length2, 0, null);
                break;
            default:
                ((SD) obj).h((RD) this.d, this.b, this.c);
                break;
        }
    }

    public /* synthetic */ C0186z(C1862b2 c1862b2, long j, int i) {
        this.d = c1862b2;
        this.c = j;
        this.b = i;
    }

    public /* synthetic */ C0186z(RD rd, int i, long j, long j2) {
        this.d = rd;
        this.b = i;
        this.c = j;
    }

    public C0186z(long j, Exception exc) {
        this.c = SystemClock.elapsedRealtime() - j;
        if (exc instanceof CameraValidator$CameraIdListIncorrectException) {
            this.b = 2;
            this.d = exc;
            return;
        }
        if (exc instanceof InitializationException) {
            Throwable cause = exc.getCause();
            exc = cause != null ? cause : exc;
            this.d = exc;
            if (exc instanceof CameraUnavailableException) {
                this.b = 2;
                return;
            } else if (exc instanceof IllegalArgumentException) {
                this.b = 1;
                return;
            } else {
                this.b = 0;
                return;
            }
        }
        this.b = 0;
        this.d = exc;
    }

    public C0186z(int i, URL url, long j) {
        this.b = i;
        this.d = url;
        this.c = j;
    }
}
