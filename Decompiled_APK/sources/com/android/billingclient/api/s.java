package com.android.billingclient.api;

import android.graphics.Bitmap;
import android.os.Parcel;
import android.util.Base64OutputStream;
import android.util.JsonWriter;
import android.util.SparseArray;
import android.view.View;
import androidx.collection.AbstractC0214l;
import androidx.collection.C0223v;
import androidx.compose.animation.core.Q;
import androidx.recyclerview.widget.R0;
import androidx.recyclerview.widget.S0;
import androidx.recyclerview.widget.X;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.ads.AbstractC2096gb;
import com.google.android.gms.internal.ads.B2;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C2107gm;
import com.google.android.gms.internal.ads.C2155hq;
import com.google.android.gms.internal.ads.C2499pr;
import com.google.android.gms.internal.ads.Ds;
import com.google.android.gms.internal.ads.Ek;
import com.google.android.gms.internal.ads.Kn;
import com.google.android.gms.internal.ads.LA;
import com.google.android.gms.internal.ads.P;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.Q5;
import com.google.android.gms.internal.ads.R5;
import com.google.android.gms.internal.ads.V3;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.Y3;
import com.google.android.gms.internal.play_billing.AbstractC3791e;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.C3794f;
import com.google.android.gms.internal.play_billing.InterfaceC3800h;
import com.google.android.gms.internal.play_billing.l2;
import com.google.android.gms.internal.play_billing.m2;
import com.google.android.gms.internal.play_billing.n2;
import com.google.android.gms.internal.play_billing.o2;
import com.google.android.gms.tasks.Task;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.PriorityQueue;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class s implements S0, com.bumptech.glide.load.resource.transcode.b, com.google.android.gms.ads.internal.util.client.e, Pv, com.google.android.gms.tasks.a, androidx.core.view.accessibility.n {
    public final /* synthetic */ int a;
    public int b;
    public Object c;

    public /* synthetic */ s(int i, char c) {
        this.a = i;
    }

    private final void q(Throwable th) {
    }

    @Override // androidx.recyclerview.widget.S0
    public X a(int i) {
        X x = (X) ((SparseArray) this.c).get(i);
        if (x != null) {
            return x;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Cannot find the wrapper for global view type "));
    }

    @Override // androidx.recyclerview.widget.S0
    public R0 b(X x) {
        return new com.quizlet.data.repository.user.e(this, x);
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        switch (this.a) {
            case 15:
                AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ((Ek) ((com.quizlet.data.repository.classmembership.c) this.c).d).d, AbstractC1642h.b(this.b));
                break;
            default:
                String str = (String) obj;
                C2155hq c2155hq = (C2155hq) this.c;
                Vp vp = c2155hq.a;
                if (!vp.i0) {
                    c2155hq.c.a(str, vp.x0, c2155hq.e, null);
                    break;
                } else {
                    String str2 = c2155hq.b.b;
                    C2499pr c2499pr = c2155hq.d;
                    c2499pr.getClass();
                    com.google.android.gms.ads.internal.j.C.k.getClass();
                    com.android.volley.toolbox.d dVar = new com.android.volley.toolbox.d(this.b, System.currentTimeMillis(), str2, str);
                    C2107gm c2107gm = c2499pr.a;
                    c2107gm.getClass();
                    c2107gm.d(new C1732Mb(26, c2107gm, dVar));
                    break;
                }
        }
    }

    @Override // com.bumptech.glide.load.resource.transcode.b
    public com.bumptech.glide.load.engine.v d(com.bumptech.glide.load.engine.v vVar, com.bumptech.glide.load.h hVar) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ((Bitmap) vVar.get()).compress((Bitmap.CompressFormat) this.c, this.b, byteArrayOutputStream);
        vVar.recycle();
        return new com.bumptech.glide.load.resource.bitmap.A(byteArrayOutputStream.toByteArray());
    }

    public Q e(Float f, int i) {
        Q q = new Q(f, androidx.compose.animation.core.C.d);
        ((C0223v) this.c).h(i, q);
        return q;
    }

    public void f() {
        WeakReference weakReference;
        int i = this.b;
        this.b = i + 1;
        if (i >= 10) {
            this.b = 0;
            Iterator it2 = ((LinkedHashMap) this.c).values().iterator();
            while (it2.hasNext()) {
                ArrayList arrayList = (ArrayList) it2.next();
                if (arrayList.size() <= 1) {
                    coil3.memory.e eVar = (coil3.memory.e) CollectionsKt.firstOrNull(arrayList);
                    if (((eVar == null || (weakReference = eVar.a) == null) ? null : (coil3.j) weakReference.get()) == null) {
                        it2.remove();
                    }
                } else {
                    int size = arrayList.size();
                    int i2 = 0;
                    for (int i3 = 0; i3 < size; i3++) {
                        int i4 = i3 - i2;
                        if (((coil3.memory.e) arrayList.get(i4)).a.get() == null) {
                            arrayList.remove(i4);
                            i2++;
                        }
                    }
                    if (arrayList.isEmpty()) {
                        it2.remove();
                    }
                }
            }
        }
    }

    @Override // androidx.core.view.accessibility.n
    public boolean g(View view) {
        ((BottomSheetBehavior) this.c).J(this.b);
        return true;
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        if (!task.l()) {
            return Boolean.FALSE;
        }
        Ds ds = (Ds) task.h();
        byte[] bArrD = ((Y3) ((V3) this.c).c()).d();
        ds.getClass();
        androidx.compose.ui.text.android.selection.f fVar = new androidx.compose.ui.text.android.selection.f(ds, bArrD);
        fVar.c = this.b;
        fVar.r();
        return Boolean.TRUE;
    }

    @Override // com.google.android.gms.ads.internal.util.client.e
    public void i(JsonWriter jsonWriter) throws IOException {
        jsonWriter.name("params").beginObject();
        jsonWriter.name("firstline").beginObject();
        jsonWriter.name("code").value(this.b);
        jsonWriter.endObject();
        com.google.android.gms.ads.internal.util.client.f.e(jsonWriter, (Map) this.c);
        jsonWriter.endObject();
    }

    public void j(int i, int i2) {
        int i3 = i2 + i;
        char[] cArr = (char[]) this.c;
        if (cArr.length <= i3) {
            int i4 = i * 2;
            if (i3 < i4) {
                i3 = i4;
            }
            char[] cArrCopyOf = Arrays.copyOf(cArr, i3);
            Intrinsics.checkNotNullExpressionValue(cArrCopyOf, "copyOf(...)");
            this.c = cArrCopyOf;
        }
    }

    public boolean k() {
        return ((com.airbnb.lottie.utils.a) this.c) != null;
    }

    public void l() {
        kotlinx.serialization.json.internal.d dVar = kotlinx.serialization.json.internal.d.c;
        char[] array = (char[]) this.c;
        dVar.getClass();
        Intrinsics.checkNotNullParameter(array, "array");
        Intrinsics.checkNotNullParameter(array, "array");
        synchronized (dVar) {
            try {
                int i = dVar.a;
                if (array.length + i < kotlinx.serialization.json.internal.c.a) {
                    dVar.a = i + array.length;
                    ((C4927s) dVar.b).addLast(array);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void m(coil3.memory.a aVar, coil3.j jVar, Map map, long j) {
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.c;
        Object arrayList = linkedHashMap.get(aVar);
        if (arrayList == null) {
            arrayList = new ArrayList();
            linkedHashMap.put(aVar, arrayList);
        }
        ArrayList arrayList2 = (ArrayList) arrayList;
        coil3.memory.e eVar = new coil3.memory.e(new WeakReference(jVar), map, j);
        if (!arrayList2.isEmpty()) {
            int size = arrayList2.size();
            int i = 0;
            while (true) {
                if (i >= size) {
                    break;
                }
                coil3.memory.e eVar2 = (coil3.memory.e) arrayList2.get(i);
                if (j < eVar2.c) {
                    i++;
                } else if (eVar2.a.get() == jVar) {
                    arrayList2.set(i, eVar);
                } else {
                    arrayList2.add(i, eVar);
                }
            }
        } else {
            arrayList2.add(eVar);
        }
        f();
    }

    public void n(String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        int length = text.length();
        if (length == 0) {
            return;
        }
        j(this.b, length);
        text.getChars(0, text.length(), (char[]) this.c, this.b);
        this.b += length;
    }

    /* JADX WARN: Type inference failed for: r3v0 */
    /* JADX WARN: Type inference failed for: r3v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v4 */
    public String o(ArrayList arrayList) throws IOException {
        StringBuilder sb = new StringBuilder();
        int size = arrayList.size();
        ?? r3 = 0;
        for (int i = 0; i < size; i++) {
            sb.append(((String) arrayList.get(i)).toLowerCase(Locale.US));
            sb.append('\n');
        }
        String[] strArrSplit = sb.toString().split("\n");
        if (strArrSplit.length == 0) {
            return "";
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(4096);
        Base64OutputStream base64OutputStream = new Base64OutputStream(byteArrayOutputStream, 10);
        B2 b2 = new B2(3);
        int i2 = this.b;
        PriorityQueue priorityQueue = new PriorityQueue(i2, b2);
        int i3 = 0;
        while (i3 < strArrSplit.length) {
            String[] strArrT = LA.t(strArrSplit[i3], r3);
            if (strArrT.length != 0) {
                int length = strArrT.length;
                if (length < 6) {
                    AbstractC2096gb.x(i2, AbstractC2096gb.D(strArrT, length), AbstractC2096gb.n(strArrT, r3, length), length, priorityQueue);
                } else {
                    long jD = AbstractC2096gb.D(strArrT, 6);
                    AbstractC2096gb.x(i2, jD, AbstractC2096gb.n(strArrT, r3, 6), 6, priorityQueue);
                    int i4 = 1;
                    while (true) {
                        int length2 = strArrT.length;
                        if (i4 < length2 - 5) {
                            int iB = LA.b(strArrT[i4 - 1]);
                            int iB2 = LA.b(strArrT[i4 + 5]);
                            int i5 = i4;
                            ByteArrayOutputStream byteArrayOutputStream2 = byteArrayOutputStream;
                            String strN = AbstractC2096gb.n(strArrT, i5, 6);
                            jD = (((iB2 + 2147483647L) % 1073807359) + (((((jD + 1073807359) - ((((iB + 2147483647L) % 1073807359) * AbstractC2096gb.c(5, 16785407L)) % 1073807359)) % 1073807359) * 16785407) % 1073807359)) % 1073807359;
                            AbstractC2096gb.x(i2, jD, strN, length2, priorityQueue);
                            i4 = i5 + 1;
                            strArrSplit = strArrSplit;
                            byteArrayOutputStream = byteArrayOutputStream2;
                        }
                    }
                }
            }
            i3++;
            strArrSplit = strArrSplit;
            byteArrayOutputStream = byteArrayOutputStream;
            r3 = 0;
        }
        ByteArrayOutputStream byteArrayOutputStream3 = byteArrayOutputStream;
        Iterator it2 = priorityQueue.iterator();
        while (it2.hasNext()) {
            try {
                base64OutputStream.write(((Q5) this.c).k1(((R5) it2.next()).b));
            } catch (IOException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Error while writing hash to byteStream", e);
            }
        }
        try {
            base64OutputStream.close();
        } catch (IOException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("HashManager: Unable to convert to Base64.", e2);
        }
        try {
            byteArrayOutputStream3.close();
            return byteArrayOutputStream3.toString();
        } catch (IOException e3) {
            com.google.android.gms.ads.internal.util.client.i.f("HashManager: Unable to convert to Base64.", e3);
            return "";
        }
    }

    public void p(m2 m2Var) {
        v vVar = (v) this.c;
        int i = this.b;
        vVar.getClass();
        try {
            if (vVar.H == null) {
                throw null;
            }
            InterfaceC3800h interfaceC3800h = vVar.H;
            String packageName = vVar.F.getPackageName();
            String str = i != 2 ? i != 3 ? i != 6 ? i != 7 ? "QUERY_SKU_DETAILS_ASYNC" : "QUERY_PRODUCT_DETAILS_ASYNC" : "START_CONNECTION" : "ACKNOWLEDGE_PURCHASE" : "LAUNCH_BILLING_FLOW";
            t tVar = new t(m2Var);
            C3794f c3794f = (C3794f) interfaceC3800h;
            Parcel parcelF4 = c3794f.f4();
            parcelF4.writeString(packageName);
            parcelF4.writeString(str);
            int i2 = AbstractC3791e.a;
            parcelF4.writeStrongBinder(tVar);
            try {
                c3794f.b.transact(1, parcelF4, null, 1);
                parcelF4.recycle();
            } catch (Throwable th) {
                parcelF4.recycle();
                throw th;
            }
        } catch (Exception e) {
            vVar.F(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 28, A.D);
            AbstractC3819n0.g("BillingClientTesting", "An error occurred while retrieving billing override.", e);
            m2Var.d = true;
            o2 o2Var = m2Var.b;
            if (o2Var != null) {
                n2 n2Var = o2Var.b;
                n2Var.getClass();
                if (l2.f.w(n2Var, null, 0)) {
                    l2.d(n2Var);
                    m2Var.a = null;
                    m2Var.b = null;
                    m2Var.c = null;
                }
            }
        }
    }

    public long r(P p) {
        int i;
        Kn kn = (Kn) this.c;
        int i2 = 0;
        p.k(kn.a, 0, 1, false);
        int i3 = kn.a[0] & 255;
        if (i3 == 0) {
            return Long.MIN_VALUE;
        }
        int i4 = 128;
        int i5 = 0;
        while (true) {
            i = i5 + 1;
            if ((i3 & i4) != 0) {
                break;
            }
            i4 >>= 1;
            i5 = i;
        }
        int i6 = i3 & (~i4);
        p.k(kn.a, 1, i5, false);
        while (i2 < i5) {
            i2++;
            i6 = (kn.a[i2] & 255) + (i6 << 8);
        }
        this.b += i;
        return i6;
    }

    public String toString() {
        switch (this.a) {
            case EventType.WINDOW_STATE /* 22 */:
                return new String((char[]) this.c, 0, this.b);
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 15:
                break;
            default:
                com.google.android.gms.ads.internal.j.C.h.h("BufferingUrlPinger.attributionReportingManager", th);
                break;
        }
    }

    public /* synthetic */ s(int i, Object obj, int i2) {
        this.a = i2;
        this.b = i;
        this.c = obj;
    }

    public /* synthetic */ s(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }

    public s(boolean z, boolean z2, boolean z3) {
        this.a = 19;
        int i = 1;
        if (!z && !z2 && !z3) {
            i = 0;
        }
        this.b = i;
    }

    public s(int i) {
        this.a = 14;
        this.c = new Q5(2);
        this.b = i;
    }

    public s(int i, byte b) {
        this.a = i;
        switch (i) {
            case 4:
                this.b = 1;
                this.c = Collections.singletonList(null);
                break;
            case 6:
                this.c = new LinkedHashMap();
                break;
            case 7:
                this.b = 255;
                this.c = null;
                break;
            case 10:
                this.c = Bitmap.CompressFormat.JPEG;
                this.b = 100;
                break;
            case 13:
                this.c = new Kn(8);
                break;
            default:
                this.b = 300;
                C0223v c0223v = AbstractC0214l.a;
                this.c = new C0223v();
                break;
        }
    }

    public s(ArrayList arrayList) {
        this.a = 4;
        this.b = 0;
        this.c = arrayList;
    }
}
