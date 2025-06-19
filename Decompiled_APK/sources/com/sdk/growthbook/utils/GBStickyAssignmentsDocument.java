package com.sdk.growthbook.utils;

import androidx.compose.animation.d0;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.F;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class GBStickyAssignmentsDocument {

    @NotNull
    private static final KSerializer[] $childSerializers;

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private final Map<String, String> assignments;

    @NotNull
    private final String attributeName;

    @NotNull
    private final String attributeValue;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return GBStickyAssignmentsDocument$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static {
        q0 q0Var = q0.a;
        $childSerializers = new KSerializer[]{null, null, new F(q0Var, q0Var, 1)};
    }

    public /* synthetic */ GBStickyAssignmentsDocument(int i, String str, String str2, Map map, l0 l0Var) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, GBStickyAssignmentsDocument$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.attributeName = str;
        this.attributeValue = str2;
        this.assignments = map;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ GBStickyAssignmentsDocument copy$default(GBStickyAssignmentsDocument gBStickyAssignmentsDocument, String str, String str2, Map map, int i, Object obj) {
        if ((i & 1) != 0) {
            str = gBStickyAssignmentsDocument.attributeName;
        }
        if ((i & 2) != 0) {
            str2 = gBStickyAssignmentsDocument.attributeValue;
        }
        if ((i & 4) != 0) {
            map = gBStickyAssignmentsDocument.assignments;
        }
        return gBStickyAssignmentsDocument.copy(str, str2, map);
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(GBStickyAssignmentsDocument gBStickyAssignmentsDocument, b bVar, SerialDescriptor serialDescriptor) {
        KSerializer[] kSerializerArr = $childSerializers;
        bVar.r(serialDescriptor, 0, gBStickyAssignmentsDocument.attributeName);
        bVar.r(serialDescriptor, 1, gBStickyAssignmentsDocument.attributeValue);
        bVar.i(serialDescriptor, 2, kSerializerArr[2], gBStickyAssignmentsDocument.assignments);
    }

    @NotNull
    public final String component1() {
        return this.attributeName;
    }

    @NotNull
    public final String component2() {
        return this.attributeValue;
    }

    @NotNull
    public final Map<String, String> component3() {
        return this.assignments;
    }

    @NotNull
    public final GBStickyAssignmentsDocument copy(@NotNull String attributeName, @NotNull String attributeValue, @NotNull Map<String, String> assignments) {
        Intrinsics.checkNotNullParameter(attributeName, "attributeName");
        Intrinsics.checkNotNullParameter(attributeValue, "attributeValue");
        Intrinsics.checkNotNullParameter(assignments, "assignments");
        return new GBStickyAssignmentsDocument(attributeName, attributeValue, assignments);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBStickyAssignmentsDocument)) {
            return false;
        }
        GBStickyAssignmentsDocument gBStickyAssignmentsDocument = (GBStickyAssignmentsDocument) obj;
        return Intrinsics.b(this.attributeName, gBStickyAssignmentsDocument.attributeName) && Intrinsics.b(this.attributeValue, gBStickyAssignmentsDocument.attributeValue) && Intrinsics.b(this.assignments, gBStickyAssignmentsDocument.assignments);
    }

    @NotNull
    public final Map<String, String> getAssignments() {
        return this.assignments;
    }

    @NotNull
    public final String getAttributeName() {
        return this.attributeName;
    }

    @NotNull
    public final String getAttributeValue() {
        return this.attributeValue;
    }

    public int hashCode() {
        return this.assignments.hashCode() + d0.e(this.attributeName.hashCode() * 31, 31, this.attributeValue);
    }

    @NotNull
    public String toString() {
        return "GBStickyAssignmentsDocument(attributeName=" + this.attributeName + ", attributeValue=" + this.attributeValue + ", assignments=" + this.assignments + ')';
    }

    public GBStickyAssignmentsDocument(@NotNull String attributeName, @NotNull String attributeValue, @NotNull Map<String, String> assignments) {
        Intrinsics.checkNotNullParameter(attributeName, "attributeName");
        Intrinsics.checkNotNullParameter(attributeValue, "attributeValue");
        Intrinsics.checkNotNullParameter(assignments, "assignments");
        this.attributeName = attributeName;
        this.attributeValue = attributeValue;
        this.assignments = assignments;
    }
}
