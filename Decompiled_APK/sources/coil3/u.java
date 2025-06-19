package coil3;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import androidx.lifecycle.C;
import androidx.lifecycle.C1247h;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j;
import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class u implements m {
    public static final /* synthetic */ int e = 0;
    public final p a;
    public final com.quizlet.data.repository.activitycenter.b b;
    public final d c;
    public volatile /* synthetic */ int d;

    static {
        AtomicIntegerFieldUpdater.newUpdater(u.class, "d");
    }

    public u(p pVar) {
        int i = 3;
        int i2 = 7;
        int i3 = 4;
        int i4 = 2;
        final int i5 = 0;
        final int i6 = 1;
        this.a = pVar;
        E.c(kotlin.coroutines.k.c(new androidx.compose.ui.text.font.o(C5041z.a, i6), E.e()));
        coil3.util.a aVar = new coil3.util.a(this);
        com.quizlet.data.repository.activitycenter.b bVar = new com.quizlet.data.repository.activitycenter.b(this);
        this.b = bVar;
        d dVar = pVar.e;
        C1608n c1608n = new C1608n();
        c1608n.a = CollectionsKt.y0(dVar.a);
        c1608n.b = CollectionsKt.y0(dVar.b);
        c1608n.c = CollectionsKt.y0(dVar.c);
        List list = (List) dVar.f.getValue();
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(new C1247h((Pair) it2.next(), i2));
        }
        c1608n.d = arrayList;
        List<coil3.decode.j> list2 = (List) dVar.g.getValue();
        ArrayList arrayList2 = new ArrayList();
        for (final coil3.decode.j jVar : list2) {
            arrayList2.add(new Function0() { // from class: coil3.c
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i5) {
                    }
                    return A.b(jVar);
                }
            });
        }
        c1608n.e = arrayList2;
        coil3.request.e eVar = pVar.b;
        Object obj = eVar.n.a.get(n.a);
        boolean zBooleanValue = ((Boolean) (obj == null ? Boolean.TRUE : obj)).booleanValue();
        ArrayList arrayList3 = (ArrayList) c1608n.d;
        ArrayList arrayList4 = (ArrayList) c1608n.e;
        if (zBooleanValue) {
            arrayList3.add(new k(i6));
            arrayList4.add(new k(i4));
        }
        c1608n.e(new coil3.map.a(i5), K.a(Uri.class));
        c1608n.e(new coil3.map.a(i), K.a(Integer.class));
        coil3.key.a aVar2 = new coil3.key.a(0);
        C4950i c4950iA = K.a(y.class);
        ArrayList arrayList5 = (ArrayList) c1608n.c;
        arrayList5.add(new Pair(aVar2, c4950iA));
        c1608n.d(new coil3.fetch.a(i5), K.a(y.class));
        c1608n.d(new coil3.fetch.a(i3), K.a(y.class));
        c1608n.d(new coil3.fetch.a(9), K.a(y.class));
        c1608n.d(new coil3.fetch.a(6), K.a(Drawable.class));
        c1608n.d(new coil3.fetch.a(i6), K.a(Bitmap.class));
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar2 = o.a;
        Object obj2 = eVar.n.a.get(o.a);
        int iIntValue = ((Number) (obj2 == null ? 4 : obj2)).intValue();
        int i7 = kotlinx.coroutines.sync.j.a;
        kotlinx.coroutines.sync.i iVar = new kotlinx.coroutines.sync.i(iIntValue, 0);
        int i8 = Build.VERSION.SDK_INT;
        Object obj3 = coil3.decode.n.b;
        if (i8 >= 29) {
            Object obj4 = eVar.n.a.get(o.c);
            if (((Boolean) (obj4 == null ? Boolean.TRUE : obj4)).booleanValue()) {
                Object obj5 = eVar.n.a.get(o.b);
                coil3.decode.n nVar = (coil3.decode.n) (obj5 == null ? obj3 : obj5);
                if (nVar.equals(obj3) || nVar.equals(coil3.decode.n.c)) {
                    final coil3.decode.u uVar = new coil3.decode.u(iVar);
                    arrayList4.add(new Function0() { // from class: coil3.c
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (i6) {
                            }
                            return A.b(uVar);
                        }
                    });
                }
            }
        }
        Object obj6 = eVar.n.a.get(o.b);
        final coil3.decode.c cVar = new coil3.decode.c(iVar, (coil3.decode.n) (obj6 != null ? obj6 : obj3));
        arrayList4.add(new Function0() { // from class: coil3.c
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i6) {
                }
                return A.b(cVar);
            }
        });
        c1608n.e(new coil3.map.a(i6), K.a(File.class));
        c1608n.d(new coil3.fetch.a(8), K.a(y.class));
        c1608n.d(new coil3.fetch.a(i), K.a(ByteBuffer.class));
        c1608n.e(new coil3.map.a(i3), K.a(String.class));
        c1608n.e(new coil3.map.a(2), K.a(okio.x.class));
        arrayList5.add(new Pair(new coil3.key.a(1), K.a(y.class)));
        arrayList5.add(new Pair(new coil3.key.a(2), K.a(y.class)));
        c1608n.d(new coil3.fetch.a(7), K.a(y.class));
        c1608n.d(new coil3.fetch.a(2), K.a(byte[].class));
        c1608n.d(new coil3.fetch.a(5), K.a(y.class));
        coil3.intercept.h hVar = new coil3.intercept.h(this, aVar, bVar);
        ArrayList arrayList6 = (ArrayList) c1608n.a;
        arrayList6.add(hVar);
        this.c = new d(AbstractC3473j.b(arrayList6), AbstractC3473j.b((ArrayList) c1608n.b), AbstractC3473j.b(arrayList5), AbstractC3473j.b(arrayList3), AbstractC3473j.b(arrayList4));
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:0|2|(2:4|(1:6)(1:7))(0)|8|(4:(1:(1:(7:13|139|14|101|(1:103)(2:104|(1:106)(2:109|110))|107|108)(2:18|19))(12:20|137|21|22|23|135|95|96|132|97|(5:100|101|(0)(0)|107|108)|99))(3:26|130|27)|134|119|(3:121|122|123)(2:126|127))(15:31|(1:33)(1:34)|35|(2:(4:38|(3:42|(1:144)(1:45)|39)|143|41)(0)|46)(0)|(1:48)(1:49)|50|(1:52)(1:53)|54|(1:56)|57|(2:(1:63)(1:62)|64)|65|140|66|(2:68|(3:70|(1:73)|99)(7:79|141|80|(5:82|(1:84)|85|(1:87)(1:88)|89)|91|(8:94|23|135|95|96|132|97|(0))|99))(2:117|118))|74|141|80|(0)|91|(0)|99|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x01ef, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x016c, code lost:
    
        r4 = r5;
        r6 = r10;
        r3 = r11;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x01b4  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x01be A[Catch: all -> 0x003d, TryCatch #5 {all -> 0x003d, blocks: (B:14:0x0038, B:101:0x01b8, B:103:0x01be, B:104:0x01cf, B:106:0x01d3, B:109:0x01df, B:110:0x01e4), top: B:139:0x0038 }] */
    /* JADX WARN: Removed duplicated region for block: B:104:0x01cf A[Catch: all -> 0x003d, TryCatch #5 {all -> 0x003d, blocks: (B:14:0x0038, B:101:0x01b8, B:103:0x01be, B:104:0x01cf, B:106:0x01d3, B:109:0x01df, B:110:0x01e4), top: B:139:0x0038 }] */
    /* JADX WARN: Removed duplicated region for block: B:121:0x01fc A[Catch: all -> 0x0209, TRY_LEAVE, TryCatch #2 {all -> 0x0209, blocks: (B:119:0x01f8, B:121:0x01fc, B:126:0x020b, B:127:0x0213), top: B:134:0x01f8 }] */
    /* JADX WARN: Removed duplicated region for block: B:126:0x020b A[Catch: all -> 0x0209, TRY_ENTER, TryCatch #2 {all -> 0x0209, blocks: (B:119:0x01f8, B:121:0x01fc, B:126:0x020b, B:127:0x0213), top: B:134:0x01f8 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x013b A[Catch: all -> 0x01ef, TryCatch #7 {all -> 0x01ef, blocks: (B:80:0x0134, B:82:0x013b, B:84:0x0145, B:85:0x014f, B:87:0x0155, B:89:0x0163, B:91:0x0170), top: B:141:0x0134 }] */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0188  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(coil3.request.g r20, int r21, kotlin.coroutines.jvm.internal.c r22) {
        /*
            Method dump skipped, instructions count: 536
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.u.a(coil3.request.g, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object b(coil3.request.g gVar, kotlin.coroutines.jvm.internal.c cVar) {
        androidx.work.impl.model.l lVar = gVar.c;
        return ((gVar.o instanceof coil3.size.f) || ((C) n.d(gVar, coil3.request.i.e)) != null) ? E.m(new r(this, gVar, null), cVar) : a(gVar, 1, cVar);
    }

    public final void c(coil3.request.c cVar, androidx.work.impl.model.l lVar, f fVar) {
        coil3.request.g gVar = cVar.b;
        fVar.getClass();
        gVar.getClass();
    }
}
