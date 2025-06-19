package com.sdk.growthbook.utils;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class GBVariationMeta {

    @NotNull
    public static final Companion Companion = new Companion(null);
    private String key;
    private String name;
    private Boolean passthrough;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return GBVariationMeta$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public GBVariationMeta() {
        this((String) null, (String) null, (Boolean) null, 7, (DefaultConstructorMarker) null);
    }

    public static /* synthetic */ GBVariationMeta copy$default(GBVariationMeta gBVariationMeta, String str, String str2, Boolean bool, int i, Object obj) {
        if ((i & 1) != 0) {
            str = gBVariationMeta.key;
        }
        if ((i & 2) != 0) {
            str2 = gBVariationMeta.name;
        }
        if ((i & 4) != 0) {
            bool = gBVariationMeta.passthrough;
        }
        return gBVariationMeta.copy(str, str2, bool);
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(GBVariationMeta gBVariationMeta, b bVar, SerialDescriptor serialDescriptor) {
        if (bVar.D(serialDescriptor) || gBVariationMeta.key != null) {
            bVar.s(serialDescriptor, 0, q0.a, gBVariationMeta.key);
        }
        if (bVar.D(serialDescriptor) || gBVariationMeta.name != null) {
            bVar.s(serialDescriptor, 1, q0.a, gBVariationMeta.name);
        }
        if (!bVar.D(serialDescriptor) && gBVariationMeta.passthrough == null) {
            return;
        }
        bVar.s(serialDescriptor, 2, C5053g.a, gBVariationMeta.passthrough);
    }

    public final String component1() {
        return this.key;
    }

    public final String component2() {
        return this.name;
    }

    public final Boolean component3() {
        return this.passthrough;
    }

    @NotNull
    public final GBVariationMeta copy(String str, String str2, Boolean bool) {
        return new GBVariationMeta(str, str2, bool);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBVariationMeta)) {
            return false;
        }
        GBVariationMeta gBVariationMeta = (GBVariationMeta) obj;
        return Intrinsics.b(this.key, gBVariationMeta.key) && Intrinsics.b(this.name, gBVariationMeta.name) && Intrinsics.b(this.passthrough, gBVariationMeta.passthrough);
    }

    public final String getKey() {
        return this.key;
    }

    public final String getName() {
        return this.name;
    }

    public final Boolean getPassthrough() {
        return this.passthrough;
    }

    public int hashCode() {
        String str = this.key;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.name;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        Boolean bool = this.passthrough;
        return iHashCode2 + (bool != null ? bool.hashCode() : 0);
    }

    public final void setKey(String str) {
        this.key = str;
    }

    public final void setName(String str) {
        this.name = str;
    }

    public final void setPassthrough(Boolean bool) {
        this.passthrough = bool;
    }

    @NotNull
    public String toString() {
        return "GBVariationMeta(key=" + this.key + ", name=" + this.name + ", passthrough=" + this.passthrough + ')';
    }

    public /* synthetic */ GBVariationMeta(int i, String str, String str2, Boolean bool, l0 l0Var) {
        if ((i & 1) == 0) {
            this.key = null;
        } else {
            this.key = str;
        }
        if ((i & 2) == 0) {
            this.name = null;
        } else {
            this.name = str2;
        }
        if ((i & 4) == 0) {
            this.passthrough = null;
        } else {
            this.passthrough = bool;
        }
    }

    public GBVariationMeta(String str, String str2, Boolean bool) {
        this.key = str;
        this.name = str2;
        this.passthrough = bool;
    }

    public /* synthetic */ GBVariationMeta(String str, String str2, Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : bool);
    }
}
