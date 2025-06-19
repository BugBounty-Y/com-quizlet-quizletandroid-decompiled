package com.sdk.growthbook.serializable_model;

import androidx.compose.animation.d0;
import com.google.android.gms.ads.g;
import com.sdk.growthbook.utils.GBFilter;
import com.sdk.growthbook.utils.GBFilter$$serializer;
import com.sdk.growthbook.utils.GBParentConditionInterface;
import com.sdk.growthbook.utils.GBParentConditionInterface$$serializer;
import com.sdk.growthbook.utils.GBVariationMeta;
import com.sdk.growthbook.utils.GBVariationMeta$$serializer;
import com.sdk.growthbook.utils.RangeSerializer;
import java.util.ArrayList;
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
import kotlinx.serialization.internal.C;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBExperiment {
    private Boolean active;
    private final Integer bucketVersion;
    private k condition;
    private Float coverage;
    private final Boolean disableStickyBucketing;
    private final String fallBackAttribute;
    private ArrayList<GBFilter> filters;
    private Integer force;
    private final String hashAttribute;
    private Integer hashVersion;

    @NotNull
    private final String key;
    private ArrayList<GBVariationMeta> meta;
    private final Integer minBucketVersion;
    private String name;
    private final d namespace;
    private final ArrayList<GBParentConditionInterface> parentConditions;
    private String phase;
    private List<Pair<Float, Float>> ranges;
    private String seed;

    @NotNull
    private final List<k> variations;
    private List<Float> weights;

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final KSerializer[] $childSerializers = {null, new C5048d(m.a, 0), null, null, new C5048d(C.a, 0), null, null, null, new C5048d(GBParentConditionInterface$$serializer.INSTANCE, 0), null, null, null, new C5048d(GBVariationMeta$$serializer.INSTANCE, 0), new C5048d(GBFilter$$serializer.INSTANCE, 0), null, null, null, null, null, null, null};

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        @NotNull
        public final KSerializer serializer() {
            return SerializableGBExperiment$$serializer.INSTANCE;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public /* synthetic */ SerializableGBExperiment(int i, String str, List list, d dVar, String str2, List list2, Boolean bool, Float f, k kVar, ArrayList arrayList, Integer num, Integer num2, List list3, ArrayList arrayList2, ArrayList arrayList3, String str3, String str4, String str5, String str6, Boolean bool2, Integer num3, Integer num4, l0 l0Var) {
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, SerializableGBExperiment$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.key = str;
        if ((i & 2) == 0) {
            this.variations = new ArrayList();
        } else {
            this.variations = list;
        }
        if ((i & 4) == 0) {
            this.namespace = null;
        } else {
            this.namespace = dVar;
        }
        if ((i & 8) == 0) {
            this.hashAttribute = null;
        } else {
            this.hashAttribute = str2;
        }
        if ((i & 16) == 0) {
            this.weights = null;
        } else {
            this.weights = list2;
        }
        if ((i & 32) == 0) {
            this.active = Boolean.TRUE;
        } else {
            this.active = bool;
        }
        if ((i & 64) == 0) {
            this.coverage = null;
        } else {
            this.coverage = f;
        }
        if ((i & 128) == 0) {
            this.condition = null;
        } else {
            this.condition = kVar;
        }
        if ((i & 256) == 0) {
            this.parentConditions = null;
        } else {
            this.parentConditions = arrayList;
        }
        if ((i & g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.force = null;
        } else {
            this.force = num;
        }
        if ((i & 1024) == 0) {
            this.hashVersion = null;
        } else {
            this.hashVersion = num2;
        }
        if ((i & 2048) == 0) {
            this.ranges = null;
        } else {
            this.ranges = list3;
        }
        if ((i & 4096) == 0) {
            this.meta = null;
        } else {
            this.meta = arrayList2;
        }
        if ((i & 8192) == 0) {
            this.filters = null;
        } else {
            this.filters = arrayList3;
        }
        if ((i & 16384) == 0) {
            this.seed = null;
        } else {
            this.seed = str3;
        }
        if ((32768 & i) == 0) {
            this.name = null;
        } else {
            this.name = str4;
        }
        if ((65536 & i) == 0) {
            this.phase = null;
        } else {
            this.phase = str5;
        }
        if ((131072 & i) == 0) {
            this.fallBackAttribute = null;
        } else {
            this.fallBackAttribute = str6;
        }
        if ((262144 & i) == 0) {
            this.disableStickyBucketing = null;
        } else {
            this.disableStickyBucketing = bool2;
        }
        if ((524288 & i) == 0) {
            this.bucketVersion = null;
        } else {
            this.bucketVersion = num3;
        }
        if ((i & 1048576) == 0) {
            this.minBucketVersion = null;
        } else {
            this.minBucketVersion = num4;
        }
    }

    public static /* synthetic */ SerializableGBExperiment copy$default(SerializableGBExperiment serializableGBExperiment, String str, List list, d dVar, String str2, List list2, Boolean bool, Float f, k kVar, ArrayList arrayList, Integer num, Integer num2, List list3, ArrayList arrayList2, ArrayList arrayList3, String str3, String str4, String str5, String str6, Boolean bool2, Integer num3, Integer num4, int i, Object obj) {
        Integer num5;
        Integer num6;
        String str7 = (i & 1) != 0 ? serializableGBExperiment.key : str;
        List list4 = (i & 2) != 0 ? serializableGBExperiment.variations : list;
        d dVar2 = (i & 4) != 0 ? serializableGBExperiment.namespace : dVar;
        String str8 = (i & 8) != 0 ? serializableGBExperiment.hashAttribute : str2;
        List list5 = (i & 16) != 0 ? serializableGBExperiment.weights : list2;
        Boolean bool3 = (i & 32) != 0 ? serializableGBExperiment.active : bool;
        Float f2 = (i & 64) != 0 ? serializableGBExperiment.coverage : f;
        k kVar2 = (i & 128) != 0 ? serializableGBExperiment.condition : kVar;
        ArrayList arrayList4 = (i & 256) != 0 ? serializableGBExperiment.parentConditions : arrayList;
        Integer num7 = (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? serializableGBExperiment.force : num;
        Integer num8 = (i & 1024) != 0 ? serializableGBExperiment.hashVersion : num2;
        List list6 = (i & 2048) != 0 ? serializableGBExperiment.ranges : list3;
        ArrayList arrayList5 = (i & 4096) != 0 ? serializableGBExperiment.meta : arrayList2;
        ArrayList arrayList6 = (i & 8192) != 0 ? serializableGBExperiment.filters : arrayList3;
        String str9 = str7;
        String str10 = (i & 16384) != 0 ? serializableGBExperiment.seed : str3;
        String str11 = (i & 32768) != 0 ? serializableGBExperiment.name : str4;
        String str12 = (i & 65536) != 0 ? serializableGBExperiment.phase : str5;
        String str13 = (i & 131072) != 0 ? serializableGBExperiment.fallBackAttribute : str6;
        Boolean bool4 = (i & 262144) != 0 ? serializableGBExperiment.disableStickyBucketing : bool2;
        Integer num9 = (i & 524288) != 0 ? serializableGBExperiment.bucketVersion : num3;
        if ((i & 1048576) != 0) {
            num6 = num9;
            num5 = serializableGBExperiment.minBucketVersion;
        } else {
            num5 = num4;
            num6 = num9;
        }
        return serializableGBExperiment.copy(str9, list4, dVar2, str8, list5, bool3, f2, kVar2, arrayList4, num7, num8, list6, arrayList5, arrayList6, str10, str11, str12, str13, bool4, num6, num5);
    }

    @f(with = RangeSerializer.GBBucketRangeListSerializer.class)
    public static /* synthetic */ void getRanges$annotations() {
    }

    public static final /* synthetic */ void write$Self$GrowthBook_release(SerializableGBExperiment serializableGBExperiment, b bVar, SerialDescriptor serialDescriptor) {
        KSerializer[] kSerializerArr = $childSerializers;
        bVar.r(serialDescriptor, 0, serializableGBExperiment.key);
        if (bVar.D(serialDescriptor) || !Intrinsics.b(serializableGBExperiment.variations, new ArrayList())) {
            bVar.i(serialDescriptor, 1, kSerializerArr[1], serializableGBExperiment.variations);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.namespace != null) {
            bVar.s(serialDescriptor, 2, kotlinx.serialization.json.f.a, serializableGBExperiment.namespace);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.hashAttribute != null) {
            bVar.s(serialDescriptor, 3, q0.a, serializableGBExperiment.hashAttribute);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.weights != null) {
            bVar.s(serialDescriptor, 4, kSerializerArr[4], serializableGBExperiment.weights);
        }
        if (bVar.D(serialDescriptor) || !Intrinsics.b(serializableGBExperiment.active, Boolean.TRUE)) {
            bVar.s(serialDescriptor, 5, C5053g.a, serializableGBExperiment.active);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.coverage != null) {
            bVar.s(serialDescriptor, 6, C.a, serializableGBExperiment.coverage);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.condition != null) {
            bVar.s(serialDescriptor, 7, m.a, serializableGBExperiment.condition);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.parentConditions != null) {
            bVar.s(serialDescriptor, 8, kSerializerArr[8], serializableGBExperiment.parentConditions);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.force != null) {
            bVar.s(serialDescriptor, 9, K.a, serializableGBExperiment.force);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.hashVersion != null) {
            bVar.s(serialDescriptor, 10, K.a, serializableGBExperiment.hashVersion);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.ranges != null) {
            bVar.s(serialDescriptor, 11, RangeSerializer.GBBucketRangeListSerializer.INSTANCE, serializableGBExperiment.ranges);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.meta != null) {
            bVar.s(serialDescriptor, 12, kSerializerArr[12], serializableGBExperiment.meta);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.filters != null) {
            bVar.s(serialDescriptor, 13, kSerializerArr[13], serializableGBExperiment.filters);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.seed != null) {
            bVar.s(serialDescriptor, 14, q0.a, serializableGBExperiment.seed);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.name != null) {
            bVar.s(serialDescriptor, 15, q0.a, serializableGBExperiment.name);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.phase != null) {
            bVar.s(serialDescriptor, 16, q0.a, serializableGBExperiment.phase);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.fallBackAttribute != null) {
            bVar.s(serialDescriptor, 17, q0.a, serializableGBExperiment.fallBackAttribute);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.disableStickyBucketing != null) {
            bVar.s(serialDescriptor, 18, C5053g.a, serializableGBExperiment.disableStickyBucketing);
        }
        if (bVar.D(serialDescriptor) || serializableGBExperiment.bucketVersion != null) {
            bVar.s(serialDescriptor, 19, K.a, serializableGBExperiment.bucketVersion);
        }
        if (!bVar.D(serialDescriptor) && serializableGBExperiment.minBucketVersion == null) {
            return;
        }
        bVar.s(serialDescriptor, 20, K.a, serializableGBExperiment.minBucketVersion);
    }

    @NotNull
    public final String component1() {
        return this.key;
    }

    public final Integer component10() {
        return this.force;
    }

    public final Integer component11() {
        return this.hashVersion;
    }

    public final List<Pair<Float, Float>> component12() {
        return this.ranges;
    }

    public final ArrayList<GBVariationMeta> component13() {
        return this.meta;
    }

    public final ArrayList<GBFilter> component14() {
        return this.filters;
    }

    public final String component15() {
        return this.seed;
    }

    public final String component16() {
        return this.name;
    }

    public final String component17() {
        return this.phase;
    }

    public final String component18() {
        return this.fallBackAttribute;
    }

    public final Boolean component19() {
        return this.disableStickyBucketing;
    }

    @NotNull
    public final List<k> component2() {
        return this.variations;
    }

    public final Integer component20() {
        return this.bucketVersion;
    }

    public final Integer component21() {
        return this.minBucketVersion;
    }

    public final d component3() {
        return this.namespace;
    }

    public final String component4() {
        return this.hashAttribute;
    }

    public final List<Float> component5() {
        return this.weights;
    }

    public final Boolean component6() {
        return this.active;
    }

    public final Float component7() {
        return this.coverage;
    }

    public final k component8() {
        return this.condition;
    }

    public final ArrayList<GBParentConditionInterface> component9() {
        return this.parentConditions;
    }

    @NotNull
    public final SerializableGBExperiment copy(@NotNull String key, @NotNull List<? extends k> variations, d dVar, String str, List<Float> list, Boolean bool, Float f, k kVar, ArrayList<GBParentConditionInterface> arrayList, Integer num, Integer num2, List<Pair<Float, Float>> list2, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str2, String str3, String str4, String str5, Boolean bool2, Integer num3, Integer num4) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(variations, "variations");
        return new SerializableGBExperiment(key, variations, dVar, str, list, bool, f, kVar, arrayList, num, num2, list2, arrayList2, arrayList3, str2, str3, str4, str5, bool2, num3, num4);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SerializableGBExperiment)) {
            return false;
        }
        SerializableGBExperiment serializableGBExperiment = (SerializableGBExperiment) obj;
        return Intrinsics.b(this.key, serializableGBExperiment.key) && Intrinsics.b(this.variations, serializableGBExperiment.variations) && Intrinsics.b(this.namespace, serializableGBExperiment.namespace) && Intrinsics.b(this.hashAttribute, serializableGBExperiment.hashAttribute) && Intrinsics.b(this.weights, serializableGBExperiment.weights) && Intrinsics.b(this.active, serializableGBExperiment.active) && Intrinsics.b(this.coverage, serializableGBExperiment.coverage) && Intrinsics.b(this.condition, serializableGBExperiment.condition) && Intrinsics.b(this.parentConditions, serializableGBExperiment.parentConditions) && Intrinsics.b(this.force, serializableGBExperiment.force) && Intrinsics.b(this.hashVersion, serializableGBExperiment.hashVersion) && Intrinsics.b(this.ranges, serializableGBExperiment.ranges) && Intrinsics.b(this.meta, serializableGBExperiment.meta) && Intrinsics.b(this.filters, serializableGBExperiment.filters) && Intrinsics.b(this.seed, serializableGBExperiment.seed) && Intrinsics.b(this.name, serializableGBExperiment.name) && Intrinsics.b(this.phase, serializableGBExperiment.phase) && Intrinsics.b(this.fallBackAttribute, serializableGBExperiment.fallBackAttribute) && Intrinsics.b(this.disableStickyBucketing, serializableGBExperiment.disableStickyBucketing) && Intrinsics.b(this.bucketVersion, serializableGBExperiment.bucketVersion) && Intrinsics.b(this.minBucketVersion, serializableGBExperiment.minBucketVersion);
    }

    public final Boolean getActive() {
        return this.active;
    }

    public final Integer getBucketVersion() {
        return this.bucketVersion;
    }

    public final k getCondition() {
        return this.condition;
    }

    public final Float getCoverage() {
        return this.coverage;
    }

    public final Boolean getDisableStickyBucketing() {
        return this.disableStickyBucketing;
    }

    public final String getFallBackAttribute() {
        return this.fallBackAttribute;
    }

    public final ArrayList<GBFilter> getFilters() {
        return this.filters;
    }

    public final Integer getForce() {
        return this.force;
    }

    public final String getHashAttribute() {
        return this.hashAttribute;
    }

    public final Integer getHashVersion() {
        return this.hashVersion;
    }

    @NotNull
    public final String getKey() {
        return this.key;
    }

    public final ArrayList<GBVariationMeta> getMeta() {
        return this.meta;
    }

    public final Integer getMinBucketVersion() {
        return this.minBucketVersion;
    }

    public final String getName() {
        return this.name;
    }

    public final d getNamespace() {
        return this.namespace;
    }

    public final ArrayList<GBParentConditionInterface> getParentConditions() {
        return this.parentConditions;
    }

    public final String getPhase() {
        return this.phase;
    }

    public final List<Pair<Float, Float>> getRanges() {
        return this.ranges;
    }

    public final String getSeed() {
        return this.seed;
    }

    @NotNull
    public final List<k> getVariations() {
        return this.variations;
    }

    public final List<Float> getWeights() {
        return this.weights;
    }

    public int hashCode() {
        int iF = d0.f(this.key.hashCode() * 31, 31, this.variations);
        d dVar = this.namespace;
        int iHashCode = (iF + (dVar == null ? 0 : dVar.a.hashCode())) * 31;
        String str = this.hashAttribute;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        List<Float> list = this.weights;
        int iHashCode3 = (iHashCode2 + (list == null ? 0 : list.hashCode())) * 31;
        Boolean bool = this.active;
        int iHashCode4 = (iHashCode3 + (bool == null ? 0 : bool.hashCode())) * 31;
        Float f = this.coverage;
        int iHashCode5 = (iHashCode4 + (f == null ? 0 : f.hashCode())) * 31;
        k kVar = this.condition;
        int iHashCode6 = (iHashCode5 + (kVar == null ? 0 : kVar.hashCode())) * 31;
        ArrayList<GBParentConditionInterface> arrayList = this.parentConditions;
        int iHashCode7 = (iHashCode6 + (arrayList == null ? 0 : arrayList.hashCode())) * 31;
        Integer num = this.force;
        int iHashCode8 = (iHashCode7 + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.hashVersion;
        int iHashCode9 = (iHashCode8 + (num2 == null ? 0 : num2.hashCode())) * 31;
        List<Pair<Float, Float>> list2 = this.ranges;
        int iHashCode10 = (iHashCode9 + (list2 == null ? 0 : list2.hashCode())) * 31;
        ArrayList<GBVariationMeta> arrayList2 = this.meta;
        int iHashCode11 = (iHashCode10 + (arrayList2 == null ? 0 : arrayList2.hashCode())) * 31;
        ArrayList<GBFilter> arrayList3 = this.filters;
        int iHashCode12 = (iHashCode11 + (arrayList3 == null ? 0 : arrayList3.hashCode())) * 31;
        String str2 = this.seed;
        int iHashCode13 = (iHashCode12 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.name;
        int iHashCode14 = (iHashCode13 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.phase;
        int iHashCode15 = (iHashCode14 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.fallBackAttribute;
        int iHashCode16 = (iHashCode15 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Boolean bool2 = this.disableStickyBucketing;
        int iHashCode17 = (iHashCode16 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Integer num3 = this.bucketVersion;
        int iHashCode18 = (iHashCode17 + (num3 == null ? 0 : num3.hashCode())) * 31;
        Integer num4 = this.minBucketVersion;
        return iHashCode18 + (num4 != null ? num4.hashCode() : 0);
    }

    public final void setActive(Boolean bool) {
        this.active = bool;
    }

    public final void setCondition(k kVar) {
        this.condition = kVar;
    }

    public final void setCoverage(Float f) {
        this.coverage = f;
    }

    public final void setFilters(ArrayList<GBFilter> arrayList) {
        this.filters = arrayList;
    }

    public final void setForce(Integer num) {
        this.force = num;
    }

    public final void setHashVersion(Integer num) {
        this.hashVersion = num;
    }

    public final void setMeta(ArrayList<GBVariationMeta> arrayList) {
        this.meta = arrayList;
    }

    public final void setName(String str) {
        this.name = str;
    }

    public final void setPhase(String str) {
        this.phase = str;
    }

    public final void setRanges(List<Pair<Float, Float>> list) {
        this.ranges = list;
    }

    public final void setSeed(String str) {
        this.seed = str;
    }

    public final void setWeights(List<Float> list) {
        this.weights = list;
    }

    @NotNull
    public String toString() {
        return "SerializableGBExperiment(key=" + this.key + ", variations=" + this.variations + ", namespace=" + this.namespace + ", hashAttribute=" + this.hashAttribute + ", weights=" + this.weights + ", active=" + this.active + ", coverage=" + this.coverage + ", condition=" + this.condition + ", parentConditions=" + this.parentConditions + ", force=" + this.force + ", hashVersion=" + this.hashVersion + ", ranges=" + this.ranges + ", meta=" + this.meta + ", filters=" + this.filters + ", seed=" + this.seed + ", name=" + this.name + ", phase=" + this.phase + ", fallBackAttribute=" + this.fallBackAttribute + ", disableStickyBucketing=" + this.disableStickyBucketing + ", bucketVersion=" + this.bucketVersion + ", minBucketVersion=" + this.minBucketVersion + ')';
    }

    /* JADX WARN: Multi-variable type inference failed */
    public SerializableGBExperiment(@NotNull String key, @NotNull List<? extends k> variations, d dVar, String str, List<Float> list, Boolean bool, Float f, k kVar, ArrayList<GBParentConditionInterface> arrayList, Integer num, Integer num2, List<Pair<Float, Float>> list2, ArrayList<GBVariationMeta> arrayList2, ArrayList<GBFilter> arrayList3, String str2, String str3, String str4, String str5, Boolean bool2, Integer num3, Integer num4) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(variations, "variations");
        this.key = key;
        this.variations = variations;
        this.namespace = dVar;
        this.hashAttribute = str;
        this.weights = list;
        this.active = bool;
        this.coverage = f;
        this.condition = kVar;
        this.parentConditions = arrayList;
        this.force = num;
        this.hashVersion = num2;
        this.ranges = list2;
        this.meta = arrayList2;
        this.filters = arrayList3;
        this.seed = str2;
        this.name = str3;
        this.phase = str4;
        this.fallBackAttribute = str5;
        this.disableStickyBucketing = bool2;
        this.bucketVersion = num3;
        this.minBucketVersion = num4;
    }

    public /* synthetic */ SerializableGBExperiment(String str, List list, d dVar, String str2, List list2, Boolean bool, Float f, k kVar, ArrayList arrayList, Integer num, Integer num2, List list3, ArrayList arrayList2, ArrayList arrayList3, String str3, String str4, String str5, String str6, Boolean bool2, Integer num3, Integer num4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, (i & 2) != 0 ? new ArrayList() : list, (i & 4) != 0 ? null : dVar, (i & 8) != 0 ? null : str2, (i & 16) != 0 ? null : list2, (i & 32) != 0 ? Boolean.TRUE : bool, (i & 64) != 0 ? null : f, (i & 128) != 0 ? null : kVar, (i & 256) != 0 ? null : arrayList, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : num, (i & 1024) != 0 ? null : num2, (i & 2048) != 0 ? null : list3, (i & 4096) != 0 ? null : arrayList2, (i & 8192) != 0 ? null : arrayList3, (i & 16384) != 0 ? null : str3, (i & 32768) != 0 ? null : str4, (i & 65536) != 0 ? null : str5, (i & 131072) != 0 ? null : str6, (i & 262144) != 0 ? null : bool2, (i & 524288) != 0 ? null : num3, (i & 1048576) != 0 ? null : num4);
    }
}
