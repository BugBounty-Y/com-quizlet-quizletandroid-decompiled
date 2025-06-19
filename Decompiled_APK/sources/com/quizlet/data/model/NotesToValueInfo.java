package com.quizlet.data.model;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class NotesToValueInfo {
    public final String a;
    public final boolean b;
    public final TitleInfo c;
    public final OutlineMarkdownInfo d;
    public final ReviewSheetInfo e;
    public final FlashcardsInfo f;
    public final EssayInfo g;
    public final User h;
    public final String i;
    public final String j;
    public final String k;
    public final long l;

    public NotesToValueInfo(String uuid, boolean z, TitleInfo titleInfo, OutlineMarkdownInfo outlineMarkdownInfo, ReviewSheetInfo reviewSheetInfo, FlashcardsInfo flashcardsInfo, EssayInfo essayInfo, User user, String originalUpload, String str, String str2) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(user, "user");
        Intrinsics.checkNotNullParameter(originalUpload, "originalUpload");
        this.a = uuid;
        this.b = z;
        this.c = titleInfo;
        this.d = outlineMarkdownInfo;
        this.e = reviewSheetInfo;
        this.f = flashcardsInfo;
        this.g = essayInfo;
        this.h = user;
        this.i = originalUpload;
        this.j = str;
        this.k = str2;
        this.l = str2 != null ? Instant.from(DateTimeFormatter.ISO_INSTANT.parse(str2)).toEpochMilli() : 0L;
    }

    public static NotesToValueInfo a(NotesToValueInfo notesToValueInfo, boolean z, TitleInfo titleInfo, OutlineMarkdownInfo outlineMarkdownInfo, FlashcardsInfo flashcardsInfo, EssayInfo essayInfo, int i) {
        String uuid = notesToValueInfo.a;
        if ((i & 2) != 0) {
            z = notesToValueInfo.b;
        }
        boolean z2 = z;
        if ((i & 4) != 0) {
            titleInfo = notesToValueInfo.c;
        }
        TitleInfo titleInfo2 = titleInfo;
        if ((i & 8) != 0) {
            outlineMarkdownInfo = notesToValueInfo.d;
        }
        OutlineMarkdownInfo outlineMarkdownInfo2 = outlineMarkdownInfo;
        ReviewSheetInfo reviewSheetInfo = notesToValueInfo.e;
        FlashcardsInfo flashcardsInfo2 = (i & 32) != 0 ? notesToValueInfo.f : flashcardsInfo;
        EssayInfo essayInfo2 = (i & 64) != 0 ? notesToValueInfo.g : essayInfo;
        User user = notesToValueInfo.h;
        String originalUpload = notesToValueInfo.i;
        String str = notesToValueInfo.j;
        String str2 = notesToValueInfo.k;
        notesToValueInfo.getClass();
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(user, "user");
        Intrinsics.checkNotNullParameter(originalUpload, "originalUpload");
        return new NotesToValueInfo(uuid, z2, titleInfo2, outlineMarkdownInfo2, reviewSheetInfo, flashcardsInfo2, essayInfo2, user, originalUpload, str, str2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof NotesToValueInfo)) {
            return false;
        }
        NotesToValueInfo notesToValueInfo = (NotesToValueInfo) obj;
        return Intrinsics.b(this.a, notesToValueInfo.a) && this.b == notesToValueInfo.b && Intrinsics.b(this.c, notesToValueInfo.c) && Intrinsics.b(this.d, notesToValueInfo.d) && Intrinsics.b(this.e, notesToValueInfo.e) && Intrinsics.b(this.f, notesToValueInfo.f) && Intrinsics.b(this.g, notesToValueInfo.g) && Intrinsics.b(this.h, notesToValueInfo.h) && Intrinsics.b(this.i, notesToValueInfo.i) && Intrinsics.b(this.j, notesToValueInfo.j) && Intrinsics.b(this.k, notesToValueInfo.k);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(this.a.hashCode() * 31, 31, this.b);
        TitleInfo titleInfo = this.c;
        int iHashCode = (iG + (titleInfo == null ? 0 : titleInfo.hashCode())) * 31;
        OutlineMarkdownInfo outlineMarkdownInfo = this.d;
        int iHashCode2 = (iHashCode + (outlineMarkdownInfo == null ? 0 : outlineMarkdownInfo.hashCode())) * 31;
        ReviewSheetInfo reviewSheetInfo = this.e;
        int iHashCode3 = (iHashCode2 + (reviewSheetInfo == null ? 0 : reviewSheetInfo.hashCode())) * 31;
        FlashcardsInfo flashcardsInfo = this.f;
        int iHashCode4 = (iHashCode3 + (flashcardsInfo == null ? 0 : flashcardsInfo.hashCode())) * 31;
        EssayInfo essayInfo = this.g;
        int iE = androidx.compose.animation.d0.e((this.h.hashCode() + ((iHashCode4 + (essayInfo == null ? 0 : essayInfo.hashCode())) * 31)) * 31, 31, this.i);
        String str = this.j;
        int iHashCode5 = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.k;
        return iHashCode5 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NotesToValueInfo(uuid=");
        sb.append(this.a);
        sb.append(", isVisible=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", outlineMarkdown=");
        sb.append(this.d);
        sb.append(", reviewSheet=");
        sb.append(this.e);
        sb.append(", flashcards=");
        sb.append(this.f);
        sb.append(", essay=");
        sb.append(this.g);
        sb.append(", user=");
        sb.append(this.h);
        sb.append(", originalUpload=");
        sb.append(this.i);
        sb.append(", userModifiedAt=");
        sb.append(this.j);
        sb.append(", createdAt=");
        return android.support.v4.media.session.a.t(sb, this.k, ")");
    }

    public /* synthetic */ NotesToValueInfo(String str, boolean z, TitleInfo titleInfo, OutlineMarkdownInfo outlineMarkdownInfo, ReviewSheetInfo reviewSheetInfo, FlashcardsInfo flashcardsInfo, EssayInfo essayInfo, User user, String str2, String str3, String str4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, z, (i & 4) != 0 ? null : titleInfo, (i & 8) != 0 ? null : outlineMarkdownInfo, (i & 16) != 0 ? null : reviewSheetInfo, (i & 32) != 0 ? null : flashcardsInfo, (i & 64) != 0 ? null : essayInfo, user, str2, (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str3, (i & 1024) != 0 ? null : str4);
    }
}
