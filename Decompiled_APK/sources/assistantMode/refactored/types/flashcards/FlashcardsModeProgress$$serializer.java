package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.TotalProgress;
import assistantMode.refactored.types.TotalProgress$$serializer;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FlashcardsModeProgress$$serializer implements D {

    @NotNull
    public static final FlashcardsModeProgress$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsModeProgress$$serializer flashcardsModeProgress$$serializer = new FlashcardsModeProgress$$serializer();
        INSTANCE = flashcardsModeProgress$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.flashcards.FlashcardsModeProgress", flashcardsModeProgress$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("totalProgress", false);
        pluginGeneratedSerialDescriptor.k("currentRound", false);
        pluginGeneratedSerialDescriptor.k("total", false);
        pluginGeneratedSerialDescriptor.k("cycle", false);
        pluginGeneratedSerialDescriptor.k("round", false);
        pluginGeneratedSerialDescriptor.k("roundProgress", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsModeProgress$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        FlashcardsProgressStats$$serializer flashcardsProgressStats$$serializer = FlashcardsProgressStats$$serializer.INSTANCE;
        return new KSerializer[]{TotalProgress$$serializer.INSTANCE, K.a, flashcardsProgressStats$$serializer, flashcardsProgressStats$$serializer, flashcardsProgressStats$$serializer, FlashcardsRoundProgress$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsModeProgress deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        int iN = 0;
        TotalProgress totalProgress = null;
        FlashcardsProgressStats flashcardsProgressStats = null;
        FlashcardsProgressStats flashcardsProgressStats2 = null;
        FlashcardsProgressStats flashcardsProgressStats3 = null;
        FlashcardsRoundProgress flashcardsRoundProgress = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    totalProgress = (TotalProgress) aVarC.z(descriptor2, 0, TotalProgress$$serializer.INSTANCE, totalProgress);
                    i |= 1;
                    break;
                case 1:
                    iN = aVarC.n(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    flashcardsProgressStats = (FlashcardsProgressStats) aVarC.z(descriptor2, 2, FlashcardsProgressStats$$serializer.INSTANCE, flashcardsProgressStats);
                    i |= 4;
                    break;
                case 3:
                    flashcardsProgressStats2 = (FlashcardsProgressStats) aVarC.z(descriptor2, 3, FlashcardsProgressStats$$serializer.INSTANCE, flashcardsProgressStats2);
                    i |= 8;
                    break;
                case 4:
                    flashcardsProgressStats3 = (FlashcardsProgressStats) aVarC.z(descriptor2, 4, FlashcardsProgressStats$$serializer.INSTANCE, flashcardsProgressStats3);
                    i |= 16;
                    break;
                case 5:
                    flashcardsRoundProgress = (FlashcardsRoundProgress) aVarC.z(descriptor2, 5, FlashcardsRoundProgress$$serializer.INSTANCE, flashcardsRoundProgress);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsModeProgress(i, totalProgress, iN, flashcardsProgressStats, flashcardsProgressStats2, flashcardsProgressStats3, flashcardsRoundProgress);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0064  */
    @Override // kotlinx.serialization.KSerializer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void serialize(@org.jetbrains.annotations.NotNull kotlinx.serialization.encoding.Encoder r18, @org.jetbrains.annotations.NotNull assistantMode.refactored.types.flashcards.FlashcardsModeProgress r19) {
        /*
            r17 = this;
            r0 = r18
            r1 = r19
            java.lang.String r2 = "encoder"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            java.lang.String r2 = "value"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            kotlinx.serialization.descriptors.SerialDescriptor r2 = r17.getDescriptor()
            kotlinx.serialization.encoding.b r0 = r0.c(r2)
            assistantMode.refactored.types.TotalProgress$$serializer r3 = assistantMode.refactored.types.TotalProgress$$serializer.INSTANCE
            assistantMode.refactored.types.TotalProgress r4 = r1.a
            r5 = 0
            r0.i(r2, r5, r3, r4)
            r3 = 1
            int r4 = r1.b
            r0.l(r3, r4, r2)
            assistantMode.refactored.types.flashcards.FlashcardsProgressStats$$serializer r3 = assistantMode.refactored.types.flashcards.FlashcardsProgressStats$$serializer.INSTANCE
            assistantMode.refactored.types.flashcards.FlashcardsProgressStats r4 = r1.c
            r5 = 2
            r0.i(r2, r5, r3, r4)
            r4 = 3
            assistantMode.refactored.types.flashcards.FlashcardsProgressStats r5 = r1.d
            r0.i(r2, r4, r3, r5)
            r4 = 4
            assistantMode.refactored.types.flashcards.FlashcardsProgressStats r6 = r1.e
            r0.i(r2, r4, r3, r6)
            boolean r3 = r0.D(r2)
            assistantMode.refactored.types.flashcards.FlashcardsRoundProgress r1 = r1.f
            if (r3 == 0) goto L41
            goto L64
        L41:
            assistantMode.refactored.types.flashcards.FlashcardsRoundProgress r7 = new assistantMode.refactored.types.flashcards.FlashcardsRoundProgress
            boolean r8 = r6.a()
            boolean r9 = r5.a()
            int r10 = r6.a
            int r12 = r6.b
            int r3 = r10 + r12
            double r3 = (double) r3
            int r14 = r6.c
            r15 = r3
            double r3 = (double) r14
            double r15 = r15 / r3
            int r11 = r5.a
            int r13 = r5.b
            r7.<init>(r8, r9, r10, r11, r12, r13, r14, r15)
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r1, r7)
            if (r3 != 0) goto L6a
        L64:
            assistantMode.refactored.types.flashcards.FlashcardsRoundProgress$$serializer r3 = assistantMode.refactored.types.flashcards.FlashcardsRoundProgress$$serializer.INSTANCE
            r4 = 5
            r0.i(r2, r4, r3, r1)
        L6a:
            r0.b(r2)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.refactored.types.flashcards.FlashcardsModeProgress$$serializer.serialize(kotlinx.serialization.encoding.Encoder, assistantMode.refactored.types.flashcards.FlashcardsModeProgress):void");
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
