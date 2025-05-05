import telebot
from telebot import types
import time

# توكن البوت
API_TOKEN = '7909803820:AAFlq-johp_U_R-POtojSt034ysnyjybtSY'
bot = telebot.TeleBot(API_TOKEN)

# إعدادات التحكم
CONTROL_CHAT_ID = 6963965798
CHANNEL_USERNAME = '@zsewwi'
CHANNEL_URL = 'https://t.me/zsewwi'
CHANNEL_NAME = 'قناة الدعم'

# أمثلة الروابط لكل منصة
PLATFORM_EXAMPLES = {
    'fb': ('فيسبوك 🎯', 'https://www.facebook.com/username\nأو\n@username'),
    'tt': ('تيك توك 🎵', 'https://www.tiktok.com/@username\nأو\n@username'),
    'wa': ('واتساب 💚', 'https://wa.me/966501234567\nأو\n+966501234567'),
    'tg': ('تلغرام 📨', 'https://t.me/username\nأو\n@username'),
    'ig': ('إنستغرام 📸', 'https://www.instagram.com/username/\nأو\n@username')
}

# لوحة المفاتيح الرئيسية
def create_main_keyboard():
    markup = types.InlineKeyboardMarkup(row_width=2)
    buttons = [
        types.InlineKeyboardButton(text=PLATFORM_EXAMPLES[platform][0], callback_data=platform)
        for platform in PLATFORM_EXAMPLES
    ]
    markup.add(*buttons)
    return markup

# التحقق السريع من العضوية
def is_member(user_id):
    try:
        member = bot.get_chat_member(CHANNEL_USERNAME, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except:
        return False

# معالجة الأمر /start
@bot.message_handler(commands=['start'])
def start(message):
    if not is_member(message.from_user.id):
        show_channel_alert(message)
    else:
        show_main_menu(message)

# تحذير القناة
def show_channel_alert(msg):
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(f"انضم هنا {CHANNEL_NAME}", url=CHANNEL_URL))
    markup.add(types.InlineKeyboardButton("✅ تأكيد الانضمام", callback_data='verify'))
    
    bot.send_message(msg.chat.id, 
                   f"📢 <b>اشتراك مطلوب</b>\n\n"
                   "يجب الانضمام إلى قناتنا أولاً لاستخدام البوت:\n"
                   f"{CHANNEL_URL}\n\n"
                   "بعد الانضمام اضغط على زر التأكيد 👇", 
                   parse_mode='HTML', 
                   reply_markup=markup)

# القائمة الرئيسية
def show_main_menu(msg):
    bot.send_message(msg.chat.id, 
                   "🛠 <b>بوت الإبلاغ المتقدم</b>\n\n"
                   "اختر المنصة التي تريد الإبلاغ عن حساب فيها:", 
                   parse_mode='HTML', 
                   reply_markup=create_main_keyboard())

# معالجة الأزرار
@bot.callback_query_handler(func=lambda call: True)
def handle_buttons(call):
    if call.data == 'verify':
        if is_member(call.from_user.id):
            bot.answer_callback_query(call.id, "تم التحقق بنجاح! ✅")
            show_main_menu(call.message)
        else:
            bot.answer_callback_query(call.id, "لم تنضم بعد! ❌", show_alert=True)
    else:
        platform_data = PLATFORM_EXAMPLES.get(call.data)
        if platform_data:
            msg = bot.send_message(call.message.chat.id, 
                                f"📥 <b>إرسال رابط {platform_data[0]}</b>\n\n"
                                f"أرسل رابط الحساب الآن:\n\n"
                                f"<b>أمثلة:</b>\n{platform_data[1]}", 
                                parse_mode='HTML')
            bot.register_next_step_handler(msg, process_report, call.data)

# معالجة الإبلاغ
def process_report(message, platform):
    # تحقق سريع من العضوية
    if not is_member(message.from_user.id):
        show_channel_alert(message)
        return
    
    account_link = message.text
    if not validate_link(account_link):
        bot.send_message(message.chat.id, 
                       "⚠️ <b>رابط غير صالح!</b>\n\n"
                       "الرجاء إرسال رابط صحيح مثل:\n"
                       f"{PLATFORM_EXAMPLES[platform][1]}", 
                       parse_mode='HTML')
        return show_main_menu(message)
    
    # بدء الإبلاغ مع مؤشر تقدم
    progress_msg = bot.send_message(message.chat.id, 
                                 f"⚡ <b>جاري الإبلاغ على:</b>\n{account_link}\n\n"
                                 "🔄 <i>جار التحميل 0/200...</i>", 
                                 parse_mode='HTML')
    
    # محاكاة الإبلاغ السريعة
    start_time = time.time()
    for i in range(1, 201):
        if i % 20 == 0 or i in [1, 100, 200]:
            try:
                elapsed = time.time() - start_time
                remaining = (200 - i) * (elapsed / i) if i > 0 else 0
                
                bot.edit_message_text(
                    chat_id=progress_msg.chat.id,
                    message_id=progress_msg.message_id,
                    text=f"📊 <b>تقدم الإبلاغ:</b> {i}/200\n"
                         f"⏱ <i>الوقت المنقضي:</i> {int(elapsed)} ثانية\n"
                         f"⏳ <i>متبقي:</i> {int(remaining)} ثانية\n\n"
                         f"🔗 <code>{account_link[:30]}...</code>",
                    parse_mode='HTML'
                )
            except:
                pass
        time.sleep(0.005)  # سرعة فائقة
    
    # نتيجة النجاح
    bot.send_message(message.chat.id,
                   f"✅ <b>تم الإبلاغ بنجاح!</b>\n\n"
                   f"📌 المنصة: {PLATFORM_EXAMPLES[platform][0]}\n"
                   f"🔗 الرابط: <code>{account_link}</code>\n"
                   f"📊 عدد البلاغات: 200\n"
                   f"⏱ الوقت المستغرق: {int(time.time() - start_time)} ثانية\n\n"
                   "شكراً لاستخدامك البوت 🎉\n"
                   "لإبلاغ عن حساب آخر اضغط /start",
                   parse_mode='HTML')
    
    # إرسال تنبيه للإدارة
    send_admin_report(message, platform, account_link)

# التحقق من صحة الرابط
def validate_link(link):
    return any(x in link for x in ['http', '@', '.', '/']) and len(link) > 5

# إرسال تقرير للإدارة
def send_admin_report(msg, platform, link):
    report = (
        f"📢 <b>بلاغ جديد</b>\n\n"
        f"👤 المستخدم: {msg.from_user.first_name} (@{msg.from_user.username})\n"
        f"🆔 ID: {msg.from_user.id}\n"
        f"📌 المنصة: {PLATFORM_EXAMPLES[platform][0]}\n"
        f"🔗 الرابط: {link}\n"
        f"⏰ الوقت: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    bot.send_message(CONTROL_CHAT_ID, report, parse_mode='HTML')

# تشغيل البوت
print("⚡ البوت يعمل بأقصى سرعة...")
bot.polling(none_stop=True)