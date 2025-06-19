package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.view.View;
import android.widget.ImageView;
import androidx.cardview.widget.CardView;
import androidx.recyclerview.widget.F0;
import com.bumptech.glide.Glide;
import com.bumptech.glide.m;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.explanations.databinding.n;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.partskit.widgets.icon.StatefulIconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.views.ContentTextView;

/* loaded from: classes3.dex */
public final class l extends F0 {
    public final Object a;
    public final ContentTextView b;
    public final ContentTextView c;
    public final ImageView d;
    public final StatefulIconFontTextView e;
    public final QStarIconView f;
    public final ColorStateList g;
    public final ColorStateList h;
    public final com.quizlet.quizletandroid.managers.audio.h i;
    public com.quizlet.data.repository.qclass.c j;

    public l(n nVar, k kVar) {
        super((CardView) nVar.c);
        this.i = (com.quizlet.quizletandroid.managers.audio.h) ((u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, this.itemView.getContext().getApplicationContext()))).f0.get();
        ContentTextView contentTextView = (ContentTextView) nVar.e;
        this.b = contentTextView;
        this.c = (ContentTextView) nVar.d;
        this.d = (ImageView) nVar.b;
        this.e = (StatefulIconFontTextView) nVar.f;
        this.f = (QStarIconView) nVar.g;
        View view = (View) contentTextView.getParent();
        view.setAccessibilityDelegate(new com.quizlet.quizletandroid.util.b(this.i, view));
        View view2 = (View) this.c.getParent();
        view2.setAccessibilityDelegate(new com.quizlet.quizletandroid.util.b(this.i, view2));
        this.a = kVar;
        this.g = this.b.getTextColors();
        this.h = this.c.getTextColors();
        final int i = 0;
        this.b.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.common.adapter.viewholder.j
            public final /* synthetic */ l b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r4v11, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v3, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v5, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v7, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v9, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                switch (i) {
                    case 0:
                        l lVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = lVar.j;
                        if (cVar != null) {
                            lVar.a.a((DBTerm) cVar.b, O1.WORD, false);
                            break;
                        }
                        break;
                    case 1:
                        l lVar2 = this.b;
                        com.quizlet.data.repository.qclass.c cVar2 = lVar2.j;
                        if (cVar2 != null) {
                            lVar2.a.a((DBTerm) cVar2.b, O1.DEFINITION, false);
                            break;
                        }
                        break;
                    case 2:
                        l lVar3 = this.b;
                        com.quizlet.data.repository.qclass.c cVar3 = lVar3.j;
                        if (cVar3 != null) {
                            lVar3.a.a((DBTerm) cVar3.b, O1.WORD, true);
                            break;
                        }
                        break;
                    case 3:
                        l lVar4 = this.b;
                        com.quizlet.data.repository.qclass.c cVar4 = lVar4.j;
                        if (cVar4 != null) {
                            lVar4.a.c((DBTerm) cVar4.b, (DBSelectedTerm) cVar4.c);
                            break;
                        }
                        break;
                    default:
                        l lVar5 = this.b;
                        com.quizlet.data.repository.qclass.c cVar5 = lVar5.j;
                        if (cVar5 != null) {
                            lVar5.a.b((DBTerm) cVar5.b);
                            break;
                        }
                        break;
                }
            }
        });
        final int i2 = 1;
        this.c.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.common.adapter.viewholder.j
            public final /* synthetic */ l b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r4v11, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v3, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v5, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v7, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v9, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                switch (i2) {
                    case 0:
                        l lVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = lVar.j;
                        if (cVar != null) {
                            lVar.a.a((DBTerm) cVar.b, O1.WORD, false);
                            break;
                        }
                        break;
                    case 1:
                        l lVar2 = this.b;
                        com.quizlet.data.repository.qclass.c cVar2 = lVar2.j;
                        if (cVar2 != null) {
                            lVar2.a.a((DBTerm) cVar2.b, O1.DEFINITION, false);
                            break;
                        }
                        break;
                    case 2:
                        l lVar3 = this.b;
                        com.quizlet.data.repository.qclass.c cVar3 = lVar3.j;
                        if (cVar3 != null) {
                            lVar3.a.a((DBTerm) cVar3.b, O1.WORD, true);
                            break;
                        }
                        break;
                    case 3:
                        l lVar4 = this.b;
                        com.quizlet.data.repository.qclass.c cVar4 = lVar4.j;
                        if (cVar4 != null) {
                            lVar4.a.c((DBTerm) cVar4.b, (DBSelectedTerm) cVar4.c);
                            break;
                        }
                        break;
                    default:
                        l lVar5 = this.b;
                        com.quizlet.data.repository.qclass.c cVar5 = lVar5.j;
                        if (cVar5 != null) {
                            lVar5.a.b((DBTerm) cVar5.b);
                            break;
                        }
                        break;
                }
            }
        });
        final int i3 = 2;
        this.e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.common.adapter.viewholder.j
            public final /* synthetic */ l b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r4v11, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v3, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v5, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v7, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v9, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                switch (i3) {
                    case 0:
                        l lVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = lVar.j;
                        if (cVar != null) {
                            lVar.a.a((DBTerm) cVar.b, O1.WORD, false);
                            break;
                        }
                        break;
                    case 1:
                        l lVar2 = this.b;
                        com.quizlet.data.repository.qclass.c cVar2 = lVar2.j;
                        if (cVar2 != null) {
                            lVar2.a.a((DBTerm) cVar2.b, O1.DEFINITION, false);
                            break;
                        }
                        break;
                    case 2:
                        l lVar3 = this.b;
                        com.quizlet.data.repository.qclass.c cVar3 = lVar3.j;
                        if (cVar3 != null) {
                            lVar3.a.a((DBTerm) cVar3.b, O1.WORD, true);
                            break;
                        }
                        break;
                    case 3:
                        l lVar4 = this.b;
                        com.quizlet.data.repository.qclass.c cVar4 = lVar4.j;
                        if (cVar4 != null) {
                            lVar4.a.c((DBTerm) cVar4.b, (DBSelectedTerm) cVar4.c);
                            break;
                        }
                        break;
                    default:
                        l lVar5 = this.b;
                        com.quizlet.data.repository.qclass.c cVar5 = lVar5.j;
                        if (cVar5 != null) {
                            lVar5.a.b((DBTerm) cVar5.b);
                            break;
                        }
                        break;
                }
            }
        });
        final int i4 = 3;
        this.f.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.common.adapter.viewholder.j
            public final /* synthetic */ l b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r4v11, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v3, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v5, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v7, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v9, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                switch (i4) {
                    case 0:
                        l lVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = lVar.j;
                        if (cVar != null) {
                            lVar.a.a((DBTerm) cVar.b, O1.WORD, false);
                            break;
                        }
                        break;
                    case 1:
                        l lVar2 = this.b;
                        com.quizlet.data.repository.qclass.c cVar2 = lVar2.j;
                        if (cVar2 != null) {
                            lVar2.a.a((DBTerm) cVar2.b, O1.DEFINITION, false);
                            break;
                        }
                        break;
                    case 2:
                        l lVar3 = this.b;
                        com.quizlet.data.repository.qclass.c cVar3 = lVar3.j;
                        if (cVar3 != null) {
                            lVar3.a.a((DBTerm) cVar3.b, O1.WORD, true);
                            break;
                        }
                        break;
                    case 3:
                        l lVar4 = this.b;
                        com.quizlet.data.repository.qclass.c cVar4 = lVar4.j;
                        if (cVar4 != null) {
                            lVar4.a.c((DBTerm) cVar4.b, (DBSelectedTerm) cVar4.c);
                            break;
                        }
                        break;
                    default:
                        l lVar5 = this.b;
                        com.quizlet.data.repository.qclass.c cVar5 = lVar5.j;
                        if (cVar5 != null) {
                            lVar5.a.b((DBTerm) cVar5.b);
                            break;
                        }
                        break;
                }
            }
        });
        final int i5 = 4;
        this.d.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.common.adapter.viewholder.j
            public final /* synthetic */ l b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r4v11, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v3, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v5, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v7, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            /* JADX WARN: Type inference failed for: r4v9, types: [com.quizlet.quizletandroid.ui.common.adapter.viewholder.k, java.lang.Object] */
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                switch (i5) {
                    case 0:
                        l lVar = this.b;
                        com.quizlet.data.repository.qclass.c cVar = lVar.j;
                        if (cVar != null) {
                            lVar.a.a((DBTerm) cVar.b, O1.WORD, false);
                            break;
                        }
                        break;
                    case 1:
                        l lVar2 = this.b;
                        com.quizlet.data.repository.qclass.c cVar2 = lVar2.j;
                        if (cVar2 != null) {
                            lVar2.a.a((DBTerm) cVar2.b, O1.DEFINITION, false);
                            break;
                        }
                        break;
                    case 2:
                        l lVar3 = this.b;
                        com.quizlet.data.repository.qclass.c cVar3 = lVar3.j;
                        if (cVar3 != null) {
                            lVar3.a.a((DBTerm) cVar3.b, O1.WORD, true);
                            break;
                        }
                        break;
                    case 3:
                        l lVar4 = this.b;
                        com.quizlet.data.repository.qclass.c cVar4 = lVar4.j;
                        if (cVar4 != null) {
                            lVar4.a.c((DBTerm) cVar4.b, (DBSelectedTerm) cVar4.c);
                            break;
                        }
                        break;
                    default:
                        l lVar5 = this.b;
                        com.quizlet.data.repository.qclass.c cVar5 = lVar5.j;
                        if (cVar5 != null) {
                            lVar5.a.b((DBTerm) cVar5.b);
                            break;
                        }
                        break;
                }
            }
        });
    }

    public final void c(DBTerm dBTerm, DBSelectedTerm dBSelectedTerm, O1 o1) {
        this.j = new com.quizlet.data.repository.qclass.c(26, dBTerm, dBSelectedTerm);
        ContentTextView contentTextView = this.b;
        O1 o12 = O1.WORD;
        contentTextView.j(B6.e(dBTerm, o12));
        ContentTextView contentTextView2 = this.c;
        O1 o13 = O1.DEFINITION;
        contentTextView2.j(B6.e(dBTerm, o13));
        this.b.setTag(R.id.quizlet_tts_url, ((DBTerm) this.j.b).getAudioUrl(o12));
        this.c.setTag(R.id.quizlet_tts_url, ((DBTerm) this.j.b).getAudioUrl(o13));
        this.e.setSelected(false);
        this.b.setTextColor(this.g);
        this.c.setTextColor(this.h);
        boolean z = true;
        if (o1 != null) {
            ContentTextView contentTextView3 = o1 == o12 ? this.b : this.c;
            this.e.setSelected(true);
            contentTextView3.setTextColor(contentTextView3.getContext().getColor(R.color.assembly_sunset400));
        }
        this.f.setSelected(dBSelectedTerm != null);
        this.d.setVisibility(dBTerm.hasDefinitionImage() ? 0 : 8);
        if (dBTerm.hasDefinitionImage()) {
            String definitionImageDefaultUrl = dBTerm.getDefinitionImageDefaultUrl(this.d.getContext().getResources().getDisplayMetrics().densityDpi);
            if (org.apache.commons.lang3.e.d(definitionImageDefaultUrl)) {
                m mVarC = Glide.c(this.d.getContext());
                mVarC.getClass();
                new com.bumptech.glide.k(mVarC.a, mVarC, Bitmap.class, mVarC.b).b(m.k).D(definitionImageDefaultUrl).z(this.d);
            }
        }
        if (org.apache.commons.lang3.e.b(dBTerm.getDefinition()) && dBTerm.hasDefinitionImage()) {
            z = false;
        }
        this.c.setVisibility(z ? 0 : 8);
        this.itemView.requestLayout();
    }
}
