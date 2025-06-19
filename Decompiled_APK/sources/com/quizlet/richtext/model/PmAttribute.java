package com.quizlet.richtext.model;

import com.quizlet.db.data.models.base.AssociationNames;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PmAttribute {
    public final String a;

    public PmAttribute(@InterfaceC4853h(name = AssociationNames.CLASS) @NotNull String attrValue) {
        Intrinsics.checkNotNullParameter(attrValue, "pmClass");
        Intrinsics.checkNotNullParameter(attrValue, "attrValue");
        this.a = attrValue;
    }

    @NotNull
    public final PmAttribute copy(@InterfaceC4853h(name = AssociationNames.CLASS) @NotNull String pmClass) {
        Intrinsics.checkNotNullParameter(pmClass, "pmClass");
        return new PmAttribute(pmClass);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof PmAttribute) && Intrinsics.b(this.a, ((PmAttribute) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PmAttribute(pmClass="), this.a, ")");
    }
}
