package com.quizlet.shared.enums.studynotes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = e.class)
/* loaded from: classes3.dex */
public final class f implements serialization.f {

    @NotNull
    public static final StudyNotesArtifactType$Companion Companion;
    public static final f b;
    public static final f c;
    public static final f d;
    public static final f e;
    public static final f f;
    public static final /* synthetic */ f[] g;
    public static final /* synthetic */ kotlin.enums.b h;
    public final String a;

    static {
        f fVar = new f("TITLE", 0, "title");
        b = fVar;
        f fVar2 = new f("ESSAY_PROMPTS", 1, "essay_prompts");
        c = fVar2;
        f fVar3 = new f("OUTLINE_MARKDOWN", 2, "outline_markdown");
        d = fVar3;
        f fVar4 = new f("TERM_SET", 3, "term_set");
        e = fVar4;
        f fVar5 = new f("REVIEW_SHEET", 4, "review_sheet");
        f = fVar5;
        f[] fVarArr = {fVar, fVar2, fVar3, fVar4, fVar5};
        g = fVarArr;
        h = AbstractC3328d.f(fVarArr);
        Companion = new StudyNotesArtifactType$Companion();
    }

    public f(String str, int i, String str2) {
        this.a = str2;
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) g.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
