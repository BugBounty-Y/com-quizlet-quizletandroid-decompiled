package androidx.navigation.compose;

import androidx.compose.animation.core.E0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.W0;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.C1291m;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ E0 j;
    public final /* synthetic */ androidx.navigation.H k;
    public final /* synthetic */ androidx.collection.B l;
    public final /* synthetic */ W0 m;
    public final /* synthetic */ C1276i n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(E0 e0, androidx.navigation.H h, androidx.collection.B b, W0 w0, C1276i c1276i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = e0;
        this.k = h;
        this.l = b;
        this.m = w0;
        this.n = c1276i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new M(this.j, this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((M) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        char c;
        char c2;
        char c3 = 7;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        E0 e0 = this.j;
        Object objT = e0.a.t();
        InterfaceC0773a0 interfaceC0773a0 = e0.d;
        if (Intrinsics.b(objT, ((L0) interfaceC0773a0).getValue())) {
            androidx.navigation.H h = this.k;
            if (((C1291m) h.b.f.k()) == null || Intrinsics.b(((L0) interfaceC0773a0).getValue(), (C1291m) h.b.f.k())) {
                Iterator it2 = ((List) this.m.getValue()).iterator();
                while (it2.hasNext()) {
                    this.n.b().c((C1291m) it2.next());
                }
                androidx.collection.B b = this.l;
                long[] jArr = b.a;
                int length = jArr.length - 2;
                if (length >= 0) {
                    int i = 0;
                    while (true) {
                        long j = jArr[i];
                        if ((((~j) << c3) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                            int i2 = 8 - ((~(i - length)) >>> 31);
                            int i3 = 0;
                            while (i3 < i2) {
                                if ((j & 255) < 128) {
                                    int i4 = (i << 3) + i3;
                                    c2 = c3;
                                    Object obj2 = b.b[i4];
                                    float f = b.c[i4];
                                    if (!Intrinsics.b((String) obj2, ((C1291m) ((L0) interfaceC0773a0).getValue()).f)) {
                                        b.e--;
                                        long[] jArr2 = b.a;
                                        int i5 = b.d;
                                        int i6 = i4 >> 3;
                                        int i7 = (i4 & 7) << 3;
                                        long j2 = (jArr2[i6] & (~(255 << i7))) | (254 << i7);
                                        jArr2[i6] = j2;
                                        jArr2[(((i4 - 7) & i5) + (i5 & 7)) >> 3] = j2;
                                        b.b[i4] = null;
                                    }
                                } else {
                                    c2 = c3;
                                }
                                j >>= 8;
                                i3++;
                                c3 = c2;
                            }
                            c = c3;
                            if (i2 != 8) {
                                break;
                            }
                        } else {
                            c = c3;
                        }
                        if (i == length) {
                            break;
                        }
                        i++;
                        c3 = c;
                    }
                }
            }
        }
        return Unit.a;
    }
}
