package com.sdk.growthbook.stickybucket;

import android.support.v4.media.session.a;
import com.google.android.gms.internal.mlkit_vision_camera.P1;
import com.sdk.growthbook.sandbox.CachingLayer;
import com.sdk.growthbook.utils.GBStickyAssignmentsDocument;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.json.b;
import kotlinx.serialization.json.c;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBStickyBucketServiceImp implements GBStickyBucketService {
    private final CachingLayer localStorage;

    @NotNull
    private final String prefix;

    /* JADX WARN: Multi-variable type inference failed */
    public GBStickyBucketServiceImp() {
        this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
    }

    @Override // com.sdk.growthbook.stickybucket.GBStickyBucketService
    @NotNull
    public Map<String, GBStickyAssignmentsDocument> getAllAssignments(@NotNull Map<String, String> attributes) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            GBStickyAssignmentsDocument assignments = getAssignments(entry.getKey(), entry.getValue());
            if (assignments != null) {
                linkedHashMap.put(assignments.getAttributeName() + "||" + assignments.getAttributeValue(), assignments);
            }
        }
        return linkedHashMap;
    }

    @Override // com.sdk.growthbook.stickybucket.GBStickyBucketService
    public GBStickyAssignmentsDocument getAssignments(@NotNull String attributeName, @NotNull String attributeValue) {
        Intrinsics.checkNotNullParameter(attributeName, "attributeName");
        Intrinsics.checkNotNullParameter(attributeValue, "attributeValue");
        StringBuilder sb = new StringBuilder();
        sb.append(attributeName);
        String strT = a.t(sb, "||", attributeValue);
        CachingLayer cachingLayer = this.localStorage;
        if (cachingLayer == null) {
            return null;
        }
        k content = cachingLayer.getContent(this.prefix + strT);
        if (content == null) {
            return null;
        }
        try {
            b bVar = c.d;
            return (GBStickyAssignmentsDocument) bVar.a(P1.d(bVar.b, K.c(GBStickyAssignmentsDocument.class)), content);
        } catch (Exception unused) {
            return null;
        }
    }

    @Override // com.sdk.growthbook.stickybucket.GBStickyBucketService
    public void saveAssignments(@NotNull GBStickyAssignmentsDocument doc) {
        Intrinsics.checkNotNullParameter(doc, "doc");
        String str = doc.getAttributeName() + "||" + doc.getAttributeValue();
        CachingLayer cachingLayer = this.localStorage;
        if (cachingLayer != null) {
            try {
                b bVar = c.d;
                String string = bVar.c(P1.d(bVar.b, K.c(GBStickyAssignmentsDocument.class)), doc);
                Intrinsics.checkNotNullParameter(string, "string");
                cachingLayer.saveContent(this.prefix + str, (k) bVar.b(string, m.a));
            } catch (Exception unused) {
            }
        }
    }

    public GBStickyBucketServiceImp(@NotNull String prefix, CachingLayer cachingLayer) {
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        this.prefix = prefix;
        this.localStorage = cachingLayer;
    }

    public /* synthetic */ GBStickyBucketServiceImp(String str, CachingLayer cachingLayer, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? "gbStickyBuckets__" : str, (i & 2) != 0 ? null : cachingLayer);
    }
}
