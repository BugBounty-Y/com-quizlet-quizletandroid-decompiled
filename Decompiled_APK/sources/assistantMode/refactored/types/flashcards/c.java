package assistantMode.refactored.types.flashcards;

import assistantMode.enums.Correctness$Companion;
import assistantMode.enums.EnumC1452f;
import com.quizlet.shared.enums.FlashcardOrdering$Companion;

/* loaded from: classes.dex */
public abstract /* synthetic */ class c {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[com.quizlet.shared.enums.d.values().length];
        try {
            iArr[0] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            FlashcardOrdering$Companion flashcardOrdering$Companion = com.quizlet.shared.enums.d.Companion;
            iArr[1] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        int[] iArr2 = new int[EnumC1452f.values().length];
        try {
            iArr2[1] = 1;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            Correctness$Companion correctness$Companion = EnumC1452f.Companion;
            iArr2[2] = 2;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            Correctness$Companion correctness$Companion2 = EnumC1452f.Companion;
            iArr2[0] = 3;
        } catch (NoSuchFieldError unused5) {
        }
        a = iArr2;
    }
}
