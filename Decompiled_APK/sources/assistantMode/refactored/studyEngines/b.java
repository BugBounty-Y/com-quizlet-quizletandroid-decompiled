package assistantMode.refactored.studyEngines;

import androidx.camera.core.impl.i0;
import assistantMode.refactored.modelTypes.d;
import assistantMode.refactored.types.FlashcardsMasteryBuckets;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.StudiableData;
import assistantMode.refactored.types.TotalProgress;
import assistantMode.refactored.types.flashcards.FlashcardsCycleSummary;
import assistantMode.refactored.types.flashcards.FlashcardsModeProgress;
import assistantMode.refactored.types.flashcards.FlashcardsModeSettings;
import assistantMode.refactored.types.flashcards.FlashcardsProgressStats;
import assistantMode.refactored.types.flashcards.FlashcardsQuestion;
import assistantMode.refactored.types.flashcards.FlashcardsRoundSummary;
import assistantMode.refactored.types.flashcards.f;
import assistantMode.refactored.types.flashcards.g;
import assistantMode.types.FlashcardsStepMetadata;
import com.google.android.gms.internal.mlkit_vision_camera.T2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.C4927s;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.e;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class b {

    @NotNull
    public static final a Companion = new a();
    public final StudiableData a;
    public FlashcardsModeSettings b;
    public final List c;
    public final ArrayList d;
    public final List e;
    public final ArrayList f;
    public List g;
    public final int h;
    public final int i;
    public final e j;
    public final c k;
    public boolean l;
    public final C4927s m;
    public final i0 n;
    public final int o;
    public final int p;
    public int q;
    public assistantMode.refactored.types.flashcards.a r;

    public b(StudiableData studiableData, FlashcardsModeSettings settings, List studiedInCycle, ArrayList remainingInCycle, List inNextCycle, ArrayList studied, List allFlashcards, int i, int i2, e random, c roundSizeStrategy) {
        Intrinsics.checkNotNullParameter(studiableData, "studiableData");
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(studiedInCycle, "studiedInCycle");
        Intrinsics.checkNotNullParameter(remainingInCycle, "remainingInCycle");
        Intrinsics.checkNotNullParameter(inNextCycle, "inNextCycle");
        Intrinsics.checkNotNullParameter(studied, "studied");
        Intrinsics.checkNotNullParameter(allFlashcards, "allFlashcards");
        Intrinsics.checkNotNullParameter(random, "random");
        Intrinsics.checkNotNullParameter(roundSizeStrategy, "roundSizeStrategy");
        this.a = studiableData;
        this.b = settings;
        this.c = studiedInCycle;
        this.d = remainingInCycle;
        this.e = inNextCycle;
        this.f = studied;
        this.g = allFlashcards;
        this.h = i;
        this.i = i2;
        this.j = random;
        this.k = roundSizeStrategy;
        this.m = new C4927s();
        i0 i0Var = new i0();
        i0Var.a = new ArrayList();
        this.n = i0Var;
        int size = studiedInCycle.size() - studied.size();
        a aVar = Companion;
        int size2 = studied.size();
        aVar.getClass();
        roundSizeStrategy.getClass();
        int iMax = Math.max(size2, i2 - size);
        this.o = iMax;
        this.p = size + iMax;
        int i3 = 0;
        if (!studied.isEmpty()) {
            Iterator it2 = studied.iterator();
            while (it2.hasNext()) {
                if (!inNextCycle.contains((RevealSelfAssessmentQuestion) it2.next()) && (i3 = i3 + 1) < 0) {
                    B.o();
                    throw null;
                }
            }
        }
        this.q = i3;
        this.r = g.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v4, types: [kotlin.random.e] */
    /* JADX WARN: Type inference failed for: r14v9, types: [java.util.List] */
    public static b d(b bVar, FlashcardsModeSettings flashcardsModeSettings, kotlin.random.g gVar, ArrayList arrayList, int i) {
        if ((i & 1) != 0) {
            flashcardsModeSettings = bVar.b;
        }
        FlashcardsModeSettings settings = flashcardsModeSettings;
        kotlin.random.g gVar2 = gVar;
        if ((i & 2) != 0) {
            gVar2 = bVar.j;
        }
        kotlin.random.g random = gVar2;
        ArrayList arrayList2 = arrayList;
        if ((i & 4) != 0) {
            arrayList2 = bVar.g;
        }
        ArrayList flashcards = arrayList2;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(random, "random");
        Intrinsics.checkNotNullParameter(flashcards, "flashcards");
        ArrayList arrayListY0 = CollectionsKt.y0(flashcards);
        List list = bVar.a.a;
        ArrayList arrayList3 = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList3.add(Long.valueOf(((d) it2.next()).getId()));
        }
        T2.e(arrayList3, arrayListY0);
        if (settings.c.ordinal() == 1) {
            CollectionsKt.h0(arrayListY0, random);
        }
        return new b(bVar.a, settings, null, arrayListY0, null, flashcards, 0, random, bVar.k, 436);
    }

    public final RevealSelfAssessmentQuestion a() {
        if (this.c.size() >= this.p) {
            return null;
        }
        return (RevealSelfAssessmentQuestion) CollectionsKt.firstOrNull(this.d);
    }

    public final f b() {
        FlashcardsStepMetadata flashcardsStepMetadata = new FlashcardsStepMetadata(this.b.d, V.c());
        if (a() == null) {
            return this.d.isEmpty() ? new FlashcardsCycleSummary(this.r, c(), flashcardsStepMetadata) : new FlashcardsRoundSummary(this.r, c(), flashcardsStepMetadata);
        }
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestionA = a();
        Intrinsics.d(revealSelfAssessmentQuestionA);
        return new FlashcardsQuestion(revealSelfAssessmentQuestionA, this.r, c(), flashcardsStepMetadata);
    }

    public final FlashcardsModeProgress c() {
        ArrayList arrayList = this.d;
        List list = this.e;
        List listM0 = CollectionsKt.m0(T2.f(CollectionsKt.c0(arrayList, list)));
        List listM02 = CollectionsKt.m0(CollectionsKt.b0(T2.f(this.g), listM0));
        boolean z = this.b.d;
        ArrayList arrayList2 = this.f;
        Pair pair = z ? new Pair(Integer.valueOf(arrayList2.size() - this.q), Integer.valueOf(list.size())) : new Pair(0, 0);
        int iIntValue = ((Number) pair.a).intValue();
        int iIntValue2 = ((Number) pair.b).intValue();
        return new FlashcardsModeProgress(new TotalProgress(new FlashcardsMasteryBuckets(listM0, listM02), (listM02.size() * 100.0d) / this.g.size()), this.h, new FlashcardsProgressStats(listM02.size(), list.size(), this.g.size()), new FlashcardsProgressStats(this.c.size() - iIntValue2, iIntValue2, this.i), new FlashcardsProgressStats(arrayList2.size() - iIntValue, iIntValue, this.o));
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ b(StudiableData studiableData, FlashcardsModeSettings flashcardsModeSettings, ArrayList arrayList, ArrayList arrayList2, ArrayList arrayList3, List list, int i, e eVar, c cVar, int i2) {
        ArrayList arrayList4 = (i2 & 4) != 0 ? new ArrayList() : arrayList;
        this(studiableData, flashcardsModeSettings, arrayList4, arrayList2, (i2 & 16) != 0 ? new ArrayList() : arrayList3, new ArrayList(), list, (i2 & 128) != 0 ? 1 : i, arrayList2.size() + arrayList4.size(), eVar, cVar);
    }
}
