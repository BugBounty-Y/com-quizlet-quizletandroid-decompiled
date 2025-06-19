package androidx.lifecycle;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.lifecycle.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public interface InterfaceC1250k extends I {
    default void onCreate(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    default void onDestroy(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    default void onPause(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    default void onResume(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    default void onStart(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    default void onStop(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }
}
