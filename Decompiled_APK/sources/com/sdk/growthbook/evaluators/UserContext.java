package com.sdk.growthbook.evaluators;

import assistantMode.refactored.a;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.utils.GBStickyAssignmentsDocument;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UserContext {

    @NotNull
    private final Map<String, GBValue> attributes;
    private final boolean qaMode;
    private Map<String, GBStickyAssignmentsDocument> stickyBucketAssignmentDocs;

    /* JADX WARN: Multi-variable type inference failed */
    public UserContext(boolean z, @NotNull Map<String, ? extends GBValue> attributes, Map<String, GBStickyAssignmentsDocument> map) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.qaMode = z;
        this.attributes = attributes;
        this.stickyBucketAssignmentDocs = map;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ UserContext copy$default(UserContext userContext, boolean z, Map map, Map map2, int i, Object obj) {
        if ((i & 1) != 0) {
            z = userContext.qaMode;
        }
        if ((i & 2) != 0) {
            map = userContext.attributes;
        }
        if ((i & 4) != 0) {
            map2 = userContext.stickyBucketAssignmentDocs;
        }
        return userContext.copy(z, map, map2);
    }

    public final boolean component1() {
        return this.qaMode;
    }

    @NotNull
    public final Map<String, GBValue> component2$GrowthBook_release() {
        return this.attributes;
    }

    public final Map<String, GBStickyAssignmentsDocument> component3$GrowthBook_release() {
        return this.stickyBucketAssignmentDocs;
    }

    @NotNull
    public final UserContext copy(boolean z, @NotNull Map<String, ? extends GBValue> attributes, Map<String, GBStickyAssignmentsDocument> map) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        return new UserContext(z, attributes, map);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UserContext)) {
            return false;
        }
        UserContext userContext = (UserContext) obj;
        return this.qaMode == userContext.qaMode && Intrinsics.b(this.attributes, userContext.attributes) && Intrinsics.b(this.stickyBucketAssignmentDocs, userContext.stickyBucketAssignmentDocs);
    }

    @NotNull
    public final Map<String, GBValue> getAttributes$GrowthBook_release() {
        return this.attributes;
    }

    public final boolean getQaMode() {
        return this.qaMode;
    }

    public final Map<String, GBStickyAssignmentsDocument> getStickyBucketAssignmentDocs$GrowthBook_release() {
        return this.stickyBucketAssignmentDocs;
    }

    public int hashCode() {
        int iD = a.d(Boolean.hashCode(this.qaMode) * 31, 31, this.attributes);
        Map<String, GBStickyAssignmentsDocument> map = this.stickyBucketAssignmentDocs;
        return iD + (map == null ? 0 : map.hashCode());
    }

    public final void setStickyBucketAssignmentDocs$GrowthBook_release(Map<String, GBStickyAssignmentsDocument> map) {
        this.stickyBucketAssignmentDocs = map;
    }

    @NotNull
    public String toString() {
        return "UserContext(qaMode=" + this.qaMode + ", attributes=" + this.attributes + ", stickyBucketAssignmentDocs=" + this.stickyBucketAssignmentDocs + ')';
    }
}
