package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.V;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.partskit.widgets.icon.StatefulIconFontTextView;
import com.quizlet.quizletandroid.ui.common.views.ContentTextView;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4755a extends V {
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d c;
    public final com.quizlet.qutils.image.loading.a d;
    public final com.quizlet.quizletandroid.managers.audio.h e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4755a(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d eventListener, com.quizlet.qutils.image.loading.a imageLoader, com.quizlet.quizletandroid.managers.audio.h audioPlayerManager) {
        super(z.d);
        Intrinsics.checkNotNullParameter(eventListener, "eventListener");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        Intrinsics.checkNotNullParameter(audioPlayerManager, "audioPlayerManager");
        this.c = eventListener;
        this.d = imageLoader;
        this.e = audioPlayerManager;
        setHasStableIds(true);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        return ((com.quizlet.learn.checkpoint.data.d) d(i)).a.a;
    }

    /* JADX WARN: Type inference failed for: r6v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        final C4756b holder = (C4756b) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Object objD = d(i);
        Intrinsics.checkNotNullExpressionValue(objD, "getItem(...)");
        final com.quizlet.learn.checkpoint.data.d card = (com.quizlet.learn.checkpoint.data.d) objD;
        holder.getClass();
        Intrinsics.checkNotNullParameter(card, "card");
        com.quizlet.features.infra.models.a aVarF = B6.f(card.a.b.c, false);
        ContentTextView contentTextView = holder.e;
        contentTextView.j(aVarF);
        final com.quizlet.studiablemodels.i iVar = card.a;
        com.quizlet.features.infra.models.a aVarF2 = B6.f(iVar.c.c, false);
        ContentTextView contentTextView2 = holder.f;
        contentTextView2.j(aVarF2);
        boolean z = card.b;
        QStarIconView qStarIconView = holder.i;
        qStarIconView.setSelected(z);
        StatefulIconFontTextView statefulIconFontTextView = holder.h;
        statefulIconFontTextView.setSelected(false);
        ColorStateList colorStateList = holder.j;
        contentTextView.setTextColor(colorStateList);
        contentTextView2.setTextColor(colorStateList);
        holder.d.dispose();
        String str = iVar.e;
        if (str == null || StringsKt.O(str)) {
            str = null;
        }
        ImageView imageView = holder.g;
        if (str != null) {
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) holder.b).a(holder.itemView.getContext()).p(str).o(imageView);
            imageView.setVisibility(0);
        } else {
            imageView.setVisibility(8);
        }
        final int i2 = 0;
        contentTextView.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i2) {
                    case 0:
                        C4756b c4756b = holder;
                        c4756b.c(card, kotlin.collections.A.b(new Pair(c4756b.e, iVar.b.e)));
                        break;
                    case 1:
                        C4756b c4756b2 = holder;
                        c4756b2.c(card, kotlin.collections.A.b(new Pair(c4756b2.f, iVar.c.e)));
                        break;
                    default:
                        C4756b c4756b3 = holder;
                        ContentTextView contentTextView3 = c4756b3.e;
                        com.quizlet.studiablemodels.i iVar2 = iVar;
                        c4756b3.c(card, kotlin.collections.B.j(new Pair(contentTextView3, iVar2.b.e), new Pair(c4756b3.f, iVar2.c.e)));
                        break;
                }
            }
        });
        final int i3 = 1;
        contentTextView2.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i3) {
                    case 0:
                        C4756b c4756b = holder;
                        c4756b.c(card, kotlin.collections.A.b(new Pair(c4756b.e, iVar.b.e)));
                        break;
                    case 1:
                        C4756b c4756b2 = holder;
                        c4756b2.c(card, kotlin.collections.A.b(new Pair(c4756b2.f, iVar.c.e)));
                        break;
                    default:
                        C4756b c4756b3 = holder;
                        ContentTextView contentTextView3 = c4756b3.e;
                        com.quizlet.studiablemodels.i iVar2 = iVar;
                        c4756b3.c(card, kotlin.collections.B.j(new Pair(contentTextView3, iVar2.b.e), new Pair(c4756b3.f, iVar2.c.e)));
                        break;
                }
            }
        });
        final int i4 = 2;
        statefulIconFontTextView.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i4) {
                    case 0:
                        C4756b c4756b = holder;
                        c4756b.c(card, kotlin.collections.A.b(new Pair(c4756b.e, iVar.b.e)));
                        break;
                    case 1:
                        C4756b c4756b2 = holder;
                        c4756b2.c(card, kotlin.collections.A.b(new Pair(c4756b2.f, iVar.c.e)));
                        break;
                    default:
                        C4756b c4756b3 = holder;
                        ContentTextView contentTextView3 = c4756b3.e;
                        com.quizlet.studiablemodels.i iVar2 = iVar;
                        c4756b3.c(card, kotlin.collections.B.j(new Pair(contentTextView3, iVar2.b.e), new Pair(c4756b3.f, iVar2.c.e)));
                        break;
                }
            }
        });
        qStarIconView.setOnClickListener(new B(holder, iVar));
        imageView.setOnClickListener(new B(iVar, holder));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        com.quizlet.explanations.databinding.n nVarA = com.quizlet.explanations.databinding.n.a(LayoutInflater.from(parent.getContext()), parent);
        Intrinsics.checkNotNullExpressionValue(nVarA, "inflate(...)");
        return new C4756b(nVarA, this.c, this.d, this.e);
    }
}
