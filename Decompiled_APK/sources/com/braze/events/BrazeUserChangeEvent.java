package com.braze.events;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class BrazeUserChangeEvent {
    private final String currentUserId;

    public BrazeUserChangeEvent(String currentUserId) {
        Intrinsics.checkNotNullParameter(currentUserId, "currentUserId");
        this.currentUserId = currentUserId;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof BrazeUserChangeEvent) && Intrinsics.b(this.currentUserId, ((BrazeUserChangeEvent) obj).currentUserId);
    }

    public final String getCurrentUserId() {
        return this.currentUserId;
    }

    public int hashCode() {
        return this.currentUserId.hashCode();
    }

    public String toString() {
        return d0.r(new StringBuilder("BrazeUserChangeEvent(currentUserId="), this.currentUserId, ')');
    }
}
