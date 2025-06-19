package com.quizlet.eventlogger.features.revisioncenter;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class RevisionCenterSource {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ RevisionCenterSource[] $VALUES;
    public static final RevisionCenterSource a;
    public static final RevisionCenterSource b;

    @NotNull
    private final String value;

    static {
        RevisionCenterSource revisionCenterSource = new RevisionCenterSource("BOTTOM_NAV_BAR", 0, "bottom_nav_bar");
        RevisionCenterSource revisionCenterSource2 = new RevisionCenterSource("FTUX", 1, "ftux");
        a = revisionCenterSource2;
        RevisionCenterSource revisionCenterSource3 = new RevisionCenterSource("HOME", 2, "home");
        b = revisionCenterSource3;
        RevisionCenterSource[] revisionCenterSourceArr = {revisionCenterSource, revisionCenterSource2, revisionCenterSource3, new RevisionCenterSource("SEARCH", 3, "search")};
        $VALUES = revisionCenterSourceArr;
        $ENTRIES = AbstractC3328d.f(revisionCenterSourceArr);
    }

    private RevisionCenterSource(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static RevisionCenterSource valueOf(String str) {
        return (RevisionCenterSource) Enum.valueOf(RevisionCenterSource.class, str);
    }

    public static RevisionCenterSource[] values() {
        return (RevisionCenterSource[]) $VALUES.clone();
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }
}
