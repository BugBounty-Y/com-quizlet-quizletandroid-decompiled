package com.quizlet.assembly.compose.listitems;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class k {
    public static final k d;
    public static final k e;
    public static final k f;
    public static final k g;
    public static final k h;
    public static final k i;
    public static final k j;
    public static final k k;
    public static final k l;
    public static final /* synthetic */ k[] m;
    public final int a;
    public final j b;
    public final int c;

    static {
        j jVar = j.e;
        k kVar = new k("Class", 0, R.drawable.ic_sys_people, jVar, R.string.quizlet_class);
        d = kVar;
        k kVar2 = new k("Course", 1, R.drawable.ic_sys_folder, jVar, R.string.course);
        j jVar2 = j.d;
        k kVar3 = new k("ExpertSolution", 2, R.drawable.ic_sys_textbook, jVar2, R.string.verified_answer);
        e = kVar3;
        k kVar4 = new k("FlashcardSet", 3, R.drawable.ic_sys_set, j.a, R.string.flashcard_set);
        f = kVar4;
        k kVar5 = new k("FlashcardSetDraft", 4, R.drawable.ic_sys_set, j.f, R.string.draft_label);
        g = kVar5;
        k kVar6 = new k("Folder", 5, R.drawable.ic_sys_folder, jVar, R.string.folder);
        h = kVar6;
        k kVar7 = new k("Notes", 6, R.drawable.ic_sys_notes, j.b, R.string.study_guide);
        i = kVar7;
        k kVar8 = new k("PracticeTest", 7, R.drawable.ic_sys_practice_test, j.c, R.string.practice_test);
        j = kVar8;
        k kVar9 = new k("Textbook", 8, R.drawable.ic_sys_textbook, jVar2, R.string.textbook);
        k = kVar9;
        k kVar10 = new k("TextbookExercise", 9, R.drawable.ic_sys_textbook, jVar2, R.string.textbook);
        l = kVar10;
        k[] kVarArr = {kVar, kVar2, kVar3, kVar4, kVar5, kVar6, kVar7, kVar8, kVar9, kVar10};
        m = kVarArr;
        AbstractC3328d.f(kVarArr);
    }

    public k(String str, int i2, int i3, j jVar, int i4) {
        this.a = i3;
        this.b = jVar;
        this.c = i4;
    }

    public static k valueOf(String str) {
        return (k) Enum.valueOf(k.class, str);
    }

    public static k[] values() {
        return (k[]) m.clone();
    }
}
