package com.sdk.growthbook.utils;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class GBParentConditionInterface {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private final k condition;
    private final Boolean gate;

    @NotNull
    private final String id;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return GBParentConditionInterface$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public /* synthetic */ GBParentConditionInterface(int i, String str, k kVar, Boolean bool, l0 l0Var) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, GBParentConditionInterface$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.id = str;
        this.condition = kVar;
        if ((i & 4) == 0) {
            this.gate = null;
        } else {
            this.gate = bool;
        }
    }

    public static /* synthetic */ GBParentConditionInterface copy$default(GBParentConditionInterface gBParentConditionInterface, String str, k kVar, Boolean bool, int i, Object obj) {
        if ((i & 1) != 0) {
            str = gBParentConditionInterface.id;
        }
        if ((i & 2) != 0) {
            kVar = gBParentConditionInterface.condition;
        }
        if ((i & 4) != 0) {
            bool = gBParentConditionInterface.gate;
        }
        return gBParentConditionInterface.copy(str, kVar, bool);
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(GBParentConditionInterface gBParentConditionInterface, b bVar, SerialDescriptor serialDescriptor) {
        bVar.r(serialDescriptor, 0, gBParentConditionInterface.id);
        bVar.i(serialDescriptor, 1, m.a, gBParentConditionInterface.condition);
        if (!bVar.D(serialDescriptor) && gBParentConditionInterface.gate == null) {
            return;
        }
        bVar.s(serialDescriptor, 2, C5053g.a, gBParentConditionInterface.gate);
    }

    @NotNull
    public final String component1() {
        return this.id;
    }

    @NotNull
    public final k component2() {
        return this.condition;
    }

    public final Boolean component3() {
        return this.gate;
    }

    @NotNull
    public final GBParentConditionInterface copy(@NotNull String id, @NotNull k condition, Boolean bool) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(condition, "condition");
        return new GBParentConditionInterface(id, condition, bool);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBParentConditionInterface)) {
            return false;
        }
        GBParentConditionInterface gBParentConditionInterface = (GBParentConditionInterface) obj;
        return Intrinsics.b(this.id, gBParentConditionInterface.id) && Intrinsics.b(this.condition, gBParentConditionInterface.condition) && Intrinsics.b(this.gate, gBParentConditionInterface.gate);
    }

    @NotNull
    public final k getCondition() {
        return this.condition;
    }

    public final Boolean getGate() {
        return this.gate;
    }

    @NotNull
    public final String getId() {
        return this.id;
    }

    public int hashCode() {
        int iHashCode = (this.condition.hashCode() + (this.id.hashCode() * 31)) * 31;
        Boolean bool = this.gate;
        return iHashCode + (bool == null ? 0 : bool.hashCode());
    }

    @NotNull
    public String toString() {
        return "GBParentConditionInterface(id=" + this.id + ", condition=" + this.condition + ", gate=" + this.gate + ')';
    }

    public GBParentConditionInterface(@NotNull String id, @NotNull k condition, Boolean bool) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(condition, "condition");
        this.id = id;
        this.condition = condition;
        this.gate = bool;
    }

    public /* synthetic */ GBParentConditionInterface(String str, k kVar, Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, kVar, (i & 4) != 0 ? null : bool);
    }
}
