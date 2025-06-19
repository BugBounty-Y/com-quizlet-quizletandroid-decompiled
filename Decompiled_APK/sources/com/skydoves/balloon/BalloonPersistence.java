package com.skydoves.balloon;

import android.content.Context;
import android.content.SharedPreferences;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonPersistence {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final String SHOWED_UP = "SHOWED_UP";
    private static volatile BalloonPersistence instance;
    private static SharedPreferences sharedPreferenceManager;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final BalloonPersistence getInstance(@NotNull Context context) {
            BalloonPersistence balloonPersistence;
            Intrinsics.checkNotNullParameter(context, "context");
            BalloonPersistence balloonPersistence2 = BalloonPersistence.instance;
            if (balloonPersistence2 != null) {
                return balloonPersistence2;
            }
            synchronized (this) {
                balloonPersistence = BalloonPersistence.instance;
                if (balloonPersistence == null) {
                    balloonPersistence = new BalloonPersistence(null);
                    BalloonPersistence.instance = balloonPersistence;
                    BalloonPersistence.sharedPreferenceManager = context.getSharedPreferences("com.skydoves.balloon", 0);
                }
            }
            return balloonPersistence;
        }

        @NotNull
        public final String getPersistName(@NotNull String name) {
            Intrinsics.checkNotNullParameter(name, "name");
            return BalloonPersistence.SHOWED_UP + name;
        }

        private Companion() {
        }
    }

    public /* synthetic */ BalloonPersistence(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    @NotNull
    public static final BalloonPersistence getInstance(@NotNull Context context) {
        return Companion.getInstance(context);
    }

    @NotNull
    public static final String getPersistName(@NotNull String str) {
        return Companion.getPersistName(str);
    }

    private final int getPersistedCounts(String str) {
        SharedPreferences sharedPreferences = sharedPreferenceManager;
        if (sharedPreferences != null) {
            return sharedPreferences.getInt(Companion.getPersistName(str), 0);
        }
        Intrinsics.m("sharedPreferenceManager");
        throw null;
    }

    private final void putCounts(String str, int i) {
        SharedPreferences sharedPreferences = sharedPreferenceManager;
        if (sharedPreferences == null) {
            Intrinsics.m("sharedPreferenceManager");
            throw null;
        }
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        editorEdit.putInt(Companion.getPersistName(str), i);
        editorEdit.apply();
    }

    public final void clearAllPreferences() {
        SharedPreferences sharedPreferences = sharedPreferenceManager;
        if (sharedPreferences == null) {
            Intrinsics.m("sharedPreferenceManager");
            throw null;
        }
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        editorEdit.clear();
        editorEdit.apply();
    }

    public final void putIncrementedCounts(@NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        putCounts(name, getPersistedCounts(name) + 1);
    }

    public final boolean shouldShowUp(@NotNull String name, int i) {
        Intrinsics.checkNotNullParameter(name, "name");
        return getPersistedCounts(name) < i;
    }

    private BalloonPersistence() {
    }
}
