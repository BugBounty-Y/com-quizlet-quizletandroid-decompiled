package kotlinx.coroutines.flow.internal;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Arrays;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.flow.internal.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4993a {
    public AbstractC4995c[] a;
    public int b;
    public int c;
    public H d;

    public final AbstractC4995c d() {
        AbstractC4995c abstractC4995cE;
        H h;
        synchronized (this) {
            try {
                AbstractC4995c[] abstractC4995cArrF = this.a;
                if (abstractC4995cArrF == null) {
                    abstractC4995cArrF = f();
                    this.a = abstractC4995cArrF;
                } else if (this.b >= abstractC4995cArrF.length) {
                    Object[] objArrCopyOf = Arrays.copyOf(abstractC4995cArrF, abstractC4995cArrF.length * 2);
                    Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
                    this.a = (AbstractC4995c[]) objArrCopyOf;
                    abstractC4995cArrF = (AbstractC4995c[]) objArrCopyOf;
                }
                int i = this.c;
                do {
                    abstractC4995cE = abstractC4995cArrF[i];
                    if (abstractC4995cE == null) {
                        abstractC4995cE = e();
                        abstractC4995cArrF[i] = abstractC4995cE;
                    }
                    i++;
                    if (i >= abstractC4995cArrF.length) {
                        i = 0;
                    }
                } while (!abstractC4995cE.a(this));
                this.c = i;
                this.b++;
                h = this.d;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (h != null) {
            h.x(1);
        }
        return abstractC4995cE;
    }

    public abstract AbstractC4995c e();

    public abstract AbstractC4995c[] f();

    public final void i(AbstractC4995c abstractC4995c) {
        H h;
        int i;
        kotlin.coroutines.h[] hVarArrB;
        synchronized (this) {
            try {
                int i2 = this.b - 1;
                this.b = i2;
                h = this.d;
                if (i2 == 0) {
                    this.c = 0;
                }
                Intrinsics.e(abstractC4995c, "null cannot be cast to non-null type kotlinx.coroutines.flow.internal.AbstractSharedFlowSlot<kotlin.Any>");
                hVarArrB = abstractC4995c.b(this);
            } catch (Throwable th) {
                throw th;
            }
        }
        for (kotlin.coroutines.h hVar : hVarArrB) {
            if (hVar != null) {
                kotlin.p pVar = kotlin.r.b;
                hVar.resumeWith(Unit.a);
            }
        }
        if (h != null) {
            h.x(-1);
        }
    }

    public final H j() {
        H h;
        synchronized (this) {
            h = this.d;
            if (h == null) {
                int i = this.b;
                h = new H(1, SubsamplingScaleImageView.TILE_SIZE_AUTO, kotlinx.coroutines.channels.a.b);
                h.h(Integer.valueOf(i));
                this.d = h;
            }
        }
        return h;
    }
}
