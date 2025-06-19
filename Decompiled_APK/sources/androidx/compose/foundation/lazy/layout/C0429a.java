package androidx.compose.foundation.lazy.layout;

import com.google.android.gms.internal.ads.AbstractC2692uC;
import com.google.android.gms.internal.ads.C1722Kd;
import com.google.android.gms.internal.ads.C1728Ld;
import com.google.android.gms.internal.ads.C2821xC;
import com.google.android.gms.internal.ads.N3;
import com.google.android.gms.internal.ads.O3;
import com.google.android.gms.internal.ads.P3;
import com.google.android.gms.internal.ads.Q3;
import com.google.android.gms.internal.mlkit_vision_barcode.T5;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import com.google.android.gms.internal.mlkit_vision_barcode.W5;
import com.google.android.gms.internal.mlkit_vision_barcode.X5;
import com.quizlet.data.model.InterfaceC4126f0;
import com.quizlet.data.model.N1;
import com.quizlet.data.model.Question;
import com.quizlet.data.model.StudyMaterialItem$ExplanationQuestionItem;
import com.quizlet.data.model.StudyMaterialItem$FlashcardSetItem;
import com.quizlet.data.model.StudyMaterialItem$FolderItem;
import com.quizlet.data.model.StudyMaterialItem$NoteItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookExerciseItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookItem;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.User;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.lazy.layout.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0429a implements io.reactivex.rxjava3.functions.i {
    public long a;

    public /* synthetic */ C0429a(long j) {
        this.a = j;
    }

    public long a() {
        return Math.max(0L, this.a - System.nanoTime());
    }

    public com.quizlet.ui.models.content.listitem.o b(N1 input) {
        Intrinsics.checkNotNullParameter(input, "input");
        boolean z = input instanceof StudyMaterialItem$FlashcardSetItem;
        long j = this.a;
        if (z) {
            StudyMaterialItem$FlashcardSetItem studyMaterialItem$FlashcardSetItem = (StudyMaterialItem$FlashcardSetItem) input;
            StudySetWithCreator studySetWithCreator = studyMaterialItem$FlashcardSetItem.b;
            User user = studySetWithCreator.b;
            String str = user != null ? user.b : null;
            boolean z2 = false;
            if (user != null && user.a == j) {
                z2 = true;
            }
            return new com.quizlet.ui.models.content.listitem.l(T5.c(studySetWithCreator.a, str, z2), ((StudyMaterialItem$FlashcardSetItem) input).a.c(), ((InterfaceC4126f0) studyMaterialItem$FlashcardSetItem.a).a(), 24);
        }
        if (input instanceof StudyMaterialItem$FolderItem) {
            StudyMaterialItem$FolderItem studyMaterialItem$FolderItem = (StudyMaterialItem$FolderItem) input;
            return new com.quizlet.ui.models.content.listitem.h(U5.c(studyMaterialItem$FolderItem.b.a), ((StudyMaterialItem$FolderItem) input).a.c(), ((InterfaceC4126f0) studyMaterialItem$FolderItem.a).a(), 24);
        }
        if (input instanceof StudyMaterialItem$TextbookItem) {
            StudyMaterialItem$TextbookItem studyMaterialItem$TextbookItem = (StudyMaterialItem$TextbookItem) input;
            return new com.quizlet.ui.models.content.listitem.n(W5.c(studyMaterialItem$TextbookItem.b), ((StudyMaterialItem$TextbookItem) input).a.c(), ((InterfaceC4126f0) studyMaterialItem$TextbookItem.a).a(), 24);
        }
        if (input instanceof StudyMaterialItem$TextbookExerciseItem) {
            StudyMaterialItem$TextbookExerciseItem studyMaterialItem$TextbookExerciseItem = (StudyMaterialItem$TextbookExerciseItem) input;
            return new com.quizlet.ui.models.content.listitem.m(X5.f(studyMaterialItem$TextbookExerciseItem.b), ((StudyMaterialItem$TextbookExerciseItem) input).a.c(), ((InterfaceC4126f0) studyMaterialItem$TextbookExerciseItem.a).a(), 24);
        }
        if (!(input instanceof StudyMaterialItem$ExplanationQuestionItem)) {
            if (!(input instanceof StudyMaterialItem$NoteItem)) {
                throw new NoWhenBranchMatchedException();
            }
            StudyMaterialItem$NoteItem studyMaterialItem$NoteItem = (StudyMaterialItem$NoteItem) input;
            return new com.quizlet.ui.models.content.listitem.i(V5.e(studyMaterialItem$NoteItem.b, j), ((StudyMaterialItem$NoteItem) input).a.c(), ((InterfaceC4126f0) studyMaterialItem$NoteItem.a).a(), 24);
        }
        StudyMaterialItem$ExplanationQuestionItem studyMaterialItem$ExplanationQuestionItem = (StudyMaterialItem$ExplanationQuestionItem) input;
        Question question = studyMaterialItem$ExplanationQuestionItem.b;
        Intrinsics.checkNotNullParameter(question, "<this>");
        String str2 = question.f.a;
        if (str2 == null) {
            str2 = "";
        }
        return new com.quizlet.ui.models.content.listitem.k(new com.quizlet.ui.models.content.listitem.c(question.d, str2), ((StudyMaterialItem$ExplanationQuestionItem) input).a.c(), ((InterfaceC4126f0) studyMaterialItem$ExplanationQuestionItem.a).a(), 24);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v14, types: [com.google.android.gms.internal.ads.xC] */
    /* JADX WARN: Type inference failed for: r9v7, types: [com.google.android.gms.internal.ads.xC] */
    public long c(ByteBuffer byteBuffer) {
        Q3 q3;
        P3 p3;
        long j = this.a;
        if (j > 0) {
            return j;
        }
        try {
            ByteBuffer byteBufferDuplicate = byteBuffer.duplicate();
            byteBufferDuplicate.flip();
            N3 n3 = new N3(new C1722Kd(byteBufferDuplicate), C1728Ld.c);
            C1722Kd c1722Kd = n3.b;
            ArrayList c2821xC = n3.f;
            if (c1722Kd != null && n3.c != AbstractC2692uC.g) {
                c2821xC = new C2821xC(c2821xC, n3);
            }
            Iterator it2 = c2821xC.iterator();
            while (true) {
                q3 = null;
                if (!it2.hasNext()) {
                    p3 = null;
                    break;
                }
                O3 o3 = (O3) it2.next();
                if (o3 instanceof P3) {
                    p3 = (P3) o3;
                    break;
                }
            }
            C1722Kd c1722Kd2 = p3.b;
            ArrayList c2821xC2 = p3.f;
            if (c1722Kd2 != null && p3.c != AbstractC2692uC.g) {
                c2821xC2 = new C2821xC(c2821xC2, p3);
            }
            Iterator it3 = c2821xC2.iterator();
            while (true) {
                if (!it3.hasNext()) {
                    break;
                }
                O3 o32 = (O3) it3.next();
                if (o32 instanceof Q3) {
                    q3 = (Q3) o32;
                    break;
                }
            }
            long j2 = (q3.m * 1000) / q3.l;
            this.a = j2;
            return j2;
        } catch (IOException | RuntimeException unused) {
            return 0L;
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        List list = (List) obj;
        Intrinsics.checkNotNullParameter(list, "list");
        if (list.size() > 1) {
            timber.log.c.a.e(new IllegalStateException(list.size() + " ImageRefs loaded for set " + this.a));
        }
        return !list.isEmpty();
    }
}
