package assistantMode.utils;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public final double a;
    public final double b;
    public final double c;
    public final double d;
    public final double e;
    public final double f;
    public final double g;
    public final double h;
    public final double i;
    public final String j;

    public d(double d, double d2, double d3, double d4, double d5, double d6, double d7, double d8, double d9, String str) {
        this.a = d;
        this.b = d2;
        this.c = d3;
        this.d = d4;
        this.e = d5;
        this.f = d6;
        this.g = d7;
        this.h = d8;
        this.i = d9;
        this.j = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Double.compare(this.a, dVar.a) == 0 && Double.compare(this.b, dVar.b) == 0 && Double.compare(this.c, dVar.c) == 0 && Double.compare(this.d, dVar.d) == 0 && Double.compare(this.e, dVar.e) == 0 && Double.compare(this.f, dVar.f) == 0 && Double.compare(this.g, dVar.g) == 0 && Double.compare(this.h, dVar.h) == 0 && Double.compare(this.i, dVar.i) == 0 && Intrinsics.b(this.j, dVar.j);
    }

    public final int hashCode() {
        int iA = d0.a(this.i, d0.a(this.h, d0.a(this.g, d0.a(this.f, d0.a(this.e, d0.a(this.d, d0.a(this.c, d0.a(this.b, Double.hashCode(this.a) * 31, 31), 31), 31), 31), 31), 31), 31), 31);
        String str = this.j;
        return iA + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DistanceMetrics(answerNormalizedEditDistance=");
        sb.append(this.a);
        sb.append(", promptNormalizedEditDistance=");
        sb.append(this.b);
        sb.append(", promptNormalizedLengthDistance=");
        sb.append(this.c);
        sb.append(", answerNormalizedLengthDistance=");
        sb.append(this.d);
        sb.append(", promptPartOfSpeechDistance=");
        sb.append(this.e);
        sb.append(", answerPartOfSpeechDistance=");
        sb.append(this.f);
        sb.append(", promptTextClassificationDistance=");
        sb.append(this.g);
        sb.append(", answerTextClassificationDistance=");
        sb.append(this.h);
        sb.append(", definitionImageDistance=");
        sb.append(this.i);
        sb.append(", optionWord=");
        return android.support.v4.media.session.a.t(sb, this.j, ")");
    }
}
