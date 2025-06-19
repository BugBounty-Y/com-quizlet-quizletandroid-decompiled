package androidx.camera.core.impl.utils;

import android.graphics.RectF;
import android.util.Rational;
import androidx.compose.runtime.internal.j;
import assistantMode.enums.k;
import assistantMode.enums.m;
import assistantMode.types.B;
import assistantMode.types.C1457d;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Comparator;

/* loaded from: classes.dex */
public final class a implements Comparator {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final Object c;

    public a(j jVar, k kVar) {
        this.b = jVar;
        this.c = kVar;
    }

    public static float a(RectF rectF, RectF rectF2) {
        return (rectF.width() < rectF2.width() ? rectF.width() : rectF2.width()) * (rectF.height() < rectF2.height() ? rectF.height() : rectF2.height());
    }

    public RectF b(Rational rational) {
        float fFloatValue = rational.floatValue();
        Rational rational2 = (Rational) this.c;
        return fFloatValue == rational2.floatValue() ? new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, rational2.getNumerator(), rational2.getDenominator()) : rational.floatValue() > rational2.floatValue() ? new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, rational2.getNumerator(), (rational.getDenominator() * rational2.getNumerator()) / rational.getNumerator()) : new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (rational.getNumerator() * rational2.getDenominator()) / rational.getDenominator(), rational2.getDenominator());
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Rational rational = (Rational) obj;
                Rational rational2 = (Rational) obj2;
                boolean z = false;
                if (rational.equals(rational2)) {
                    return 0;
                }
                RectF rectFB = b(rational);
                RectF rectFB2 = b(rational2);
                RectF rectF = (RectF) this.b;
                boolean z2 = rectFB.width() >= rectF.width() && rectFB.height() >= rectF.height();
                if (rectFB2.width() >= rectF.width() && rectFB2.height() >= rectF.height()) {
                    z = true;
                }
                if (z2 && z) {
                    return (int) Math.signum((rectFB.height() * rectFB.width()) - (rectFB2.height() * rectFB2.width()));
                }
                if (z2) {
                    return -1;
                }
                if (z) {
                    return 1;
                }
                return -((int) Math.signum(a(rectFB, rectF) - a(rectFB2, rectF)));
            default:
                C1457d c1457d = ((B) obj).a;
                long j = c1457d.a.a.a;
                m mVar = c1457d.c;
                j jVar = (j) this.b;
                k kVar = (k) this.c;
                Integer numValueOf = Integer.valueOf(jVar.f(j, kVar, mVar));
                C1457d c1457d2 = ((B) obj2).a;
                return kotlin.comparisons.a.b(numValueOf, Integer.valueOf(jVar.f(c1457d2.a.a.a, kVar, c1457d2.c)));
        }
    }

    public a(Rational rational, Rational rational2) {
        this.c = rational2 == null ? new Rational(4, 3) : rational2;
        this.b = b(rational);
    }
}
