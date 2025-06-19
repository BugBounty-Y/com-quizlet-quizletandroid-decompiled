package com.quizlet.shared.schemas.eventlogger.events;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlinx.serialization.f;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@f(with = a.class)
/* loaded from: classes3.dex */
public final class b implements serialization.f {

    @NotNull
    public static final LoggingEventType$Companion Companion;
    public static final /* synthetic */ b[] b;
    public final String a;

    static {
        b[] bVarArr = {new b("QUESTION_EVENTS", 0, "question_events"), new b("TEXT_GRADING_EVENTS", 1, "text_grading_events")};
        b = bVarArr;
        AbstractC3328d.f(bVarArr);
        Companion = new LoggingEventType$Companion();
    }

    public b(String str, int i, String str2) {
        this.a = str2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) b.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
