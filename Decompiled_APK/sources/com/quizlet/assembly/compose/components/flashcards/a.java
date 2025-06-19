package com.quizlet.assembly.compose.components.flashcards;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class a extends b {
    public static final a c = new a(180.0f, 0);
    public static final a d = new a(DefinitionKt.NO_Float_VALUE, 1);
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(float f, int i) {
        super(f);
        this.b = i;
    }

    @Override // com.quizlet.assembly.compose.components.flashcards.b
    public final b a() {
        switch (this.b) {
            case 0:
                return d;
            default:
                return c;
        }
    }
}
