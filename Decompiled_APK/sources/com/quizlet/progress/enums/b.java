package com.quizlet.progress.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b {
    public static final com.google.firebase.perf.logging.b b;
    public static final b c;
    public static final b d;
    public static final b e;
    public static final b f;
    public static final b g;
    public static final b h;
    public static final b i;
    public static final b j;
    public static final b k;
    public static final b l;
    public static final b m;
    public static final b n;
    public static final b o;
    public static final /* synthetic */ b[] p;
    public final int a;

    static {
        b bVar = new b("WRITE", 0, 1);
        b bVar2 = new b("FLASHCARDS", 1, 2);
        c = bVar2;
        b bVar3 = new b("TEST", 2, 3);
        b bVar4 = new b("SPACE_RACE", 3, 4);
        d = bVar4;
        b bVar5 = new b("SCATTER", 4, 5);
        e = bVar5;
        b bVar6 = new b("VOICE_RACE", 5, 6);
        f = bVar6;
        b bVar7 = new b("VOICE_SCATTER", 6, 7);
        g = bVar7;
        b bVar8 = new b("SPELLER", 7, 8);
        b bVar9 = new b("BISMARCK", 8, 9);
        h = bVar9;
        b bVar10 = new b("MOBILE_CARDS", 9, 10);
        b bVar11 = new b("MOBILE_WRITE", 10, 11);
        b bVar12 = new b("MOBILE_SCATTER", 11, 12);
        i = bVar12;
        b bVar13 = new b("GRAVITY", 12, 13);
        j = bVar13;
        b bVar14 = new b("MICROSCATTER", 13, 14);
        k = bVar14;
        b bVar15 = new b("REVIEW", 14, 15);
        l = bVar15;
        b bVar16 = new b("MULTIPLAYER", 15, 16);
        m = bVar16;
        b bVar17 = new b("LEARNING_ASSISTANT", 16, 17);
        b bVar18 = new b("LOCATE", 17, 18);
        n = bVar18;
        b bVar19 = new b("LIVE_WITH_FRIENDS", 18, 19);
        o = bVar19;
        b[] bVarArr = {bVar, bVar2, bVar3, bVar4, bVar5, bVar6, bVar7, bVar8, bVar9, bVar10, bVar11, bVar12, bVar13, bVar14, bVar15, bVar16, bVar17, bVar18, bVar19, new b("QCHAT", 19, 20)};
        p = bVarArr;
        AbstractC3328d.f(bVarArr);
        b = new com.google.firebase.perf.logging.b(29);
    }

    public b(String str, int i2, int i3) {
        this.a = i3;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) p.clone();
    }
}
