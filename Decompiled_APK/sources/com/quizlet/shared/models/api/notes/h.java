package com.quizlet.shared.models.api.notes;

import kotlin.l;
import kotlin.m;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
/* loaded from: classes3.dex */
public abstract class h {

    @NotNull
    public static final StudyNotesRequest$Companion Companion = new StudyNotesRequest$Companion();
    public static final Object b = l.a(m.b, g.a);
    public final String a;

    public h(String str) {
        this.a = str;
    }

    public String a() {
        return this.a;
    }
}
