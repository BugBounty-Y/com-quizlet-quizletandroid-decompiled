package com.sdk.growthbook.utils;

import com.sdk.growthbook.utils.RangeSerializer;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class GBFilter {

    @NotNull
    public static final Companion Companion = new Companion(null);
    private String attribute;
    private String fallbackAttribute;
    private Integer hashVersion;

    @NotNull
    private List<Pair<Float, Float>> ranges;

    @NotNull
    private String seed;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return GBFilter$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public /* synthetic */ GBFilter(int i, String str, List list, String str2, Integer num, String str3, l0 l0Var) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, GBFilter$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.seed = str;
        this.ranges = list;
        if ((i & 4) == 0) {
            this.attribute = null;
        } else {
            this.attribute = str2;
        }
        if ((i & 8) == 0) {
            this.hashVersion = null;
        } else {
            this.hashVersion = num;
        }
        if ((i & 16) == 0) {
            this.fallbackAttribute = null;
        } else {
            this.fallbackAttribute = str3;
        }
    }

    @f(with = RangeSerializer.GBBucketRangeListSerializer.class)
    public static /* synthetic */ void getRanges$annotations() {
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(GBFilter gBFilter, b bVar, SerialDescriptor serialDescriptor) {
        bVar.r(serialDescriptor, 0, gBFilter.seed);
        bVar.i(serialDescriptor, 1, RangeSerializer.GBBucketRangeListSerializer.INSTANCE, gBFilter.ranges);
        if (bVar.D(serialDescriptor) || gBFilter.attribute != null) {
            bVar.s(serialDescriptor, 2, q0.a, gBFilter.attribute);
        }
        if (bVar.D(serialDescriptor) || gBFilter.hashVersion != null) {
            bVar.s(serialDescriptor, 3, K.a, gBFilter.hashVersion);
        }
        if (!bVar.D(serialDescriptor) && gBFilter.fallbackAttribute == null) {
            return;
        }
        bVar.s(serialDescriptor, 4, q0.a, gBFilter.fallbackAttribute);
    }

    public final String getAttribute() {
        return this.attribute;
    }

    public final String getFallbackAttribute() {
        return this.fallbackAttribute;
    }

    public final Integer getHashVersion() {
        return this.hashVersion;
    }

    @NotNull
    public final List<Pair<Float, Float>> getRanges() {
        return this.ranges;
    }

    @NotNull
    public final String getSeed() {
        return this.seed;
    }

    public final void setAttribute(String str) {
        this.attribute = str;
    }

    public final void setFallbackAttribute(String str) {
        this.fallbackAttribute = str;
    }

    public final void setHashVersion(Integer num) {
        this.hashVersion = num;
    }

    public final void setRanges(@NotNull List<Pair<Float, Float>> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.ranges = list;
    }

    public final void setSeed(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.seed = str;
    }

    public GBFilter(@NotNull String seed, @NotNull List<Pair<Float, Float>> ranges, String str, Integer num, String str2) {
        Intrinsics.checkNotNullParameter(seed, "seed");
        Intrinsics.checkNotNullParameter(ranges, "ranges");
        this.seed = seed;
        this.ranges = ranges;
        this.attribute = str;
        this.hashVersion = num;
        this.fallbackAttribute = str2;
    }

    public /* synthetic */ GBFilter(String str, List list, String str2, Integer num, String str3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, list, (i & 4) != 0 ? null : str2, (i & 8) != 0 ? null : num, (i & 16) != 0 ? null : str3);
    }
}
