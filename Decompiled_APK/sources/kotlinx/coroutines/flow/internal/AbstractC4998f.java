package kotlinx.coroutines.flow.internal;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5038w;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: kotlinx.coroutines.flow.internal.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4998f implements z {
    public final CoroutineContext a;
    public final int b;
    public final kotlinx.coroutines.channels.a c;

    public AbstractC4998f(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        this.a = coroutineContext;
        this.b = i;
        this.c = aVar;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        Object objM = kotlinx.coroutines.E.m(new C4996d(interfaceC5002j, this, null), hVar);
        return objM == kotlin.coroutines.intrinsics.a.a ? objM : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0015  */
    @Override // kotlinx.coroutines.flow.internal.z
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlinx.coroutines.flow.InterfaceC4992i c(kotlin.coroutines.CoroutineContext r5, int r6, kotlinx.coroutines.channels.a r7) {
        /*
            r4 = this;
            kotlin.coroutines.CoroutineContext r0 = r4.a
            kotlin.coroutines.CoroutineContext r5 = r5.plus(r0)
            kotlinx.coroutines.channels.a r1 = kotlinx.coroutines.channels.a.a
            kotlinx.coroutines.channels.a r2 = r4.c
            int r3 = r4.b
            if (r7 == r1) goto Lf
            goto L26
        Lf:
            r7 = -3
            if (r3 != r7) goto L13
            goto L25
        L13:
            if (r6 != r7) goto L17
        L15:
            r6 = r3
            goto L25
        L17:
            r7 = -2
            if (r3 != r7) goto L1b
            goto L25
        L1b:
            if (r6 != r7) goto L1e
            goto L15
        L1e:
            int r6 = r6 + r3
            if (r6 < 0) goto L22
            goto L25
        L22:
            r6 = 2147483647(0x7fffffff, float:NaN)
        L25:
            r7 = r2
        L26:
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r5, r0)
            if (r0 == 0) goto L31
            if (r6 != r3) goto L31
            if (r7 != r2) goto L31
            return r4
        L31:
            kotlinx.coroutines.flow.internal.f r5 = r4.f(r5, r6, r7)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.internal.AbstractC4998f.c(kotlin.coroutines.CoroutineContext, int, kotlinx.coroutines.channels.a):kotlinx.coroutines.flow.i");
    }

    public String d() {
        return null;
    }

    public abstract Object e(kotlinx.coroutines.channels.u uVar, kotlin.coroutines.h hVar);

    public abstract AbstractC4998f f(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar);

    public InterfaceC4992i i() {
        return null;
    }

    public kotlinx.coroutines.channels.w j(kotlinx.coroutines.C c) {
        int i = this.b;
        if (i == -3) {
            i = -2;
        }
        kotlinx.coroutines.D d = kotlinx.coroutines.D.c;
        Function2 c4997e = new C4997e(this, null);
        kotlinx.coroutines.channels.t tVar = new kotlinx.coroutines.channels.t(AbstractC5038w.b(c, this.a), D1.a(i, 4, this.c), true, true);
        tVar.m0(d, tVar, c4997e);
        return tVar;
    }

    public String toString() {
        ArrayList arrayList = new ArrayList(4);
        String strD = d();
        if (strD != null) {
            arrayList.add(strD);
        }
        kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
        CoroutineContext coroutineContext = this.a;
        if (coroutineContext != nVar) {
            arrayList.add("context=" + coroutineContext);
        }
        int i = this.b;
        if (i != -3) {
            arrayList.add("capacity=" + i);
        }
        kotlinx.coroutines.channels.a aVar = kotlinx.coroutines.channels.a.a;
        kotlinx.coroutines.channels.a aVar2 = this.c;
        if (aVar2 != aVar) {
            arrayList.add("onBufferOverflow=" + aVar2);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append('[');
        return d0.r(sb, CollectionsKt.S(arrayList, ", ", null, null, null, 62), ']');
    }
}
