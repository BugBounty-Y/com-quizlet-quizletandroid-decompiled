package com.quizlet.db.data.models.base;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class SortOption {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ SortOption[] $VALUES;

    @NotNull
    public static final Companion Companion;
    private final int value;
    public static final SortOption ORIGINAL = new SortOption("ORIGINAL", 0, 0);
    public static final SortOption ALPHABETICAL_BY_WORD = new SortOption("ALPHABETICAL_BY_WORD", 1, 1);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final SortOption fromInt(int i) {
            SortOption sortOption;
            SortOption[] sortOptionArrValues = SortOption.values();
            int length = sortOptionArrValues.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    sortOption = null;
                    break;
                }
                sortOption = sortOptionArrValues[i2];
                if (sortOption.getValue() == i) {
                    break;
                }
                i2++;
            }
            if (sortOption != null) {
                return sortOption;
            }
            throw new IllegalArgumentException("Invalid sort option");
        }

        private Companion() {
        }
    }

    private static final /* synthetic */ SortOption[] $values() {
        return new SortOption[]{ORIGINAL, ALPHABETICAL_BY_WORD};
    }

    static {
        SortOption[] sortOptionArr$values = $values();
        $VALUES = sortOptionArr$values;
        $ENTRIES = AbstractC3328d.f(sortOptionArr$values);
        Companion = new Companion(null);
    }

    private SortOption(String str, int i, int i2) {
        this.value = i2;
    }

    @NotNull
    public static final SortOption fromInt(int i) {
        return Companion.fromInt(i);
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static SortOption valueOf(String str) {
        return (SortOption) Enum.valueOf(SortOption.class, str);
    }

    public static SortOption[] values() {
        return (SortOption[]) $VALUES.clone();
    }

    public final int getValue() {
        return this.value;
    }
}
