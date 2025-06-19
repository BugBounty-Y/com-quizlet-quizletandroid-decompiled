package com.quizlet.utm.mediums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.utm.c;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b implements c {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ b[] $VALUES;

    @NotNull
    public static final a Companion;
    public static final b SHARE_LINK = new b("SHARE_LINK", 0, "share-link");

    @NotNull
    private final String value;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final b fromValue(String str) {
            for (b bVar : b.values()) {
                if (Intrinsics.b(bVar.getValue(), str)) {
                    return bVar;
                }
            }
            return null;
        }

        private a() {
        }
    }

    private static final /* synthetic */ b[] $values() {
        return new b[]{SHARE_LINK};
    }

    static {
        b[] bVarArr$values = $values();
        $VALUES = bVarArr$values;
        $ENTRIES = AbstractC3328d.f(bVarArr$values);
        Companion = new a(null);
    }

    private b(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) $VALUES.clone();
    }

    @Override // com.quizlet.utm.c
    @NotNull
    public String getValue() {
        return this.value;
    }
}
