package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.content.res.ColorStateList;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.recyclerview.widget.F0;
import com.quizlet.features.setpage.viewmodel.C4430d;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.partskit.widgets.icon.StatefulIconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.ContentTextView;
import com.quizlet.studiablemodels.StudiableAudio;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4756b extends F0 {
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d a;
    public final com.quizlet.qutils.image.loading.a b;
    public final com.quizlet.quizletandroid.managers.audio.h c;
    public AtomicReference d;
    public final ContentTextView e;
    public final ContentTextView f;
    public final ImageView g;
    public final StatefulIconFontTextView h;
    public final QStarIconView i;
    public final ColorStateList j;
    public final int k;

    /* JADX WARN: Illegal instructions before constructor call */
    public C4756b(com.quizlet.explanations.databinding.n binding, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d listener, com.quizlet.qutils.image.loading.a imageLoader, com.quizlet.quizletandroid.managers.audio.h audioPlayerManager) {
        Intrinsics.checkNotNullParameter(binding, "binding");
        Intrinsics.checkNotNullParameter(listener, "listener");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        Intrinsics.checkNotNullParameter(audioPlayerManager, "audioPlayerManager");
        CardView itemView = (CardView) binding.c;
        Intrinsics.checkNotNullExpressionValue(itemView, "getRoot(...)");
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(listener, "listener");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        Intrinsics.checkNotNullParameter(audioPlayerManager, "audioPlayerManager");
        super(itemView);
        this.a = listener;
        this.b = imageLoader;
        this.c = audioPlayerManager;
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.d = dVar;
        ContentTextView listitemTermWord = (ContentTextView) binding.e;
        Intrinsics.checkNotNullExpressionValue(listitemTermWord, "listitemTermWord");
        this.e = listitemTermWord;
        ContentTextView listitemTermDefinition = (ContentTextView) binding.d;
        Intrinsics.checkNotNullExpressionValue(listitemTermDefinition, "listitemTermDefinition");
        this.f = listitemTermDefinition;
        ImageView listitemTermDefinitionImage = (ImageView) binding.b;
        Intrinsics.checkNotNullExpressionValue(listitemTermDefinitionImage, "listitemTermDefinitionImage");
        this.g = listitemTermDefinitionImage;
        StatefulIconFontTextView setpageDiagramAudio = (StatefulIconFontTextView) binding.f;
        Intrinsics.checkNotNullExpressionValue(setpageDiagramAudio, "setpageDiagramAudio");
        this.h = setpageDiagramAudio;
        QStarIconView setpageDiagramStar = (QStarIconView) binding.g;
        Intrinsics.checkNotNullExpressionValue(setpageDiagramStar, "setpageDiagramStar");
        this.i = setpageDiagramStar;
        ColorStateList textColors = listitemTermWord.getTextColors();
        Intrinsics.checkNotNullExpressionValue(textColors, "getTextColors(...)");
        this.j = textColors;
        this.k = R.attr.textColorActivated;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    public final void c(com.quizlet.learn.checkpoint.data.d dVar, List list) {
        io.reactivex.rxjava3.internal.functions.b bVar;
        com.quizlet.infra.legacysyncengine.net.request.g gVar;
        this.d.dispose();
        io.reactivex.rxjava3.core.a aVar = io.reactivex.rxjava3.internal.operators.completable.f.a;
        Intrinsics.checkNotNullExpressionValue(aVar, "complete(...)");
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (((StudiableAudio) ((Pair) obj).b) != null) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            bVar = io.reactivex.rxjava3.internal.functions.d.c;
            gVar = io.reactivex.rxjava3.internal.functions.d.d;
            if (!zHasNext) {
                break;
            }
            Pair pair = (Pair) it2.next();
            TextView textView = (TextView) pair.a;
            StudiableAudio studiableAudio = (StudiableAudio) pair.b;
            Intrinsics.d(studiableAudio);
            arrayList2.add(new io.reactivex.rxjava3.internal.operators.completable.a(1, new io.reactivex.rxjava3.internal.operators.completable.i(this.c.a(studiableAudio.a), new com.quizlet.billing.manager.b(18, textView, this), gVar, bVar, bVar), new C4430d(4, textView, this)));
        }
        Iterator it3 = arrayList2.iterator();
        io.reactivex.rxjava3.core.a aVar2 = aVar;
        while (it3.hasNext()) {
            io.reactivex.rxjava3.core.a aVar3 = (io.reactivex.rxjava3.core.a) it3.next();
            Objects.requireNonNull(aVar3, "next is null");
            aVar2 = new io.reactivex.rxjava3.internal.operators.completable.a(0, aVar2, aVar3);
        }
        this.d = (AtomicReference) new io.reactivex.rxjava3.internal.operators.completable.a(1, new io.reactivex.rxjava3.internal.operators.completable.i(aVar2, new com.quizlet.quizletandroid.ui.setpage.terms.c(this, 2), gVar, bVar, bVar), new com.quizlet.eventlogger.e(this, 20)).e();
        long j = dVar.a.a;
        this.a.getClass();
    }
}
