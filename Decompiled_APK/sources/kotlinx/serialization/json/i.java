package kotlinx.serialization.json;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final String f;
    public final String g;
    public final boolean h;
    public final boolean i;
    public final a j;

    public i(boolean z, boolean z2, boolean z3, boolean z4, boolean z5, String prettyPrintIndent, String classDiscriminator, boolean z6, boolean z7, a classDiscriminatorMode) {
        Intrinsics.checkNotNullParameter(prettyPrintIndent, "prettyPrintIndent");
        Intrinsics.checkNotNullParameter(classDiscriminator, "classDiscriminator");
        Intrinsics.checkNotNullParameter(classDiscriminatorMode, "classDiscriminatorMode");
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
        this.e = z5;
        this.f = prettyPrintIndent;
        this.g = classDiscriminator;
        this.h = z6;
        this.i = z7;
        this.j = classDiscriminatorMode;
    }

    public final String toString() {
        return "JsonConfiguration(encodeDefaults=" + this.a + ", ignoreUnknownKeys=" + this.b + ", isLenient=" + this.c + ", allowStructuredMapKeys=false, prettyPrint=" + this.d + ", explicitNulls=" + this.e + ", prettyPrintIndent='" + this.f + "', coerceInputValues=false, useArrayPolymorphism=false, classDiscriminator='" + this.g + "', allowSpecialFloatingPointValues=" + this.h + ", useAlternativeNames=" + this.i + ", namingStrategy=null, decodeEnumsCaseInsensitive=false, allowTrailingComma=false, allowComments=false, classDiscriminatorMode=" + this.j + ')';
    }
}
