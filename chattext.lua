-- سكريبت شات SZ_STORE النهائي - نسخة محصنة + تبديل ذكي (مصحّح ومصغّر)
local _G_ = getgenv and getgenv() or _G
local _game = game
local _Instance_new = Instance.new
local _HttpService = _game:GetService("HttpService")
local _Players = _game:GetService("Players")
local _CoreGui = _game:GetService("CoreGui")
local _LocalPlayer = _Players.LocalPlayer
local JOB_ID = _game.JobId

local BASE_URL = "https://sz-chet-default-rtdb.firebaseio.com"
local LAST_SEND = 0
local CurrentMode = "Global"

local LoadedMessages = {
    Global = {},
    Local = {}
}

-- [دالة طرد متوافقة مع جميع المحركات: تجرب Kick الرسمي، وإن فشل تستخدم بديلاً فعلياً]
local function forceKickPlayer(reason)
    -- المحاولة الأولى: الطرد الرسمي تبع روبلوكس
    local kicked = pcall(function()
        _Players.LocalPlayer:Kick(reason)
    end)

    if not kicked then
        warn("[فحص الحظر] Kick الرسمي غير مدعوم بهذا المحرك، تفعيل البديل اليدوي")

        -- البديل: تعطيل الشخصية بالكامل + شاشة طرد مزيفة تطابق شكل الطرد الرسمي
        pcall(function()
            local char = _LocalPlayer.Character
            if char then
                local hum = char:FindFirstChildOfClass("Humanoid")
                if hum then hum.Health = 0 end
            end
        end)

        -- إيقاف أي محاولة Respawn
        pcall(function()
            _LocalPlayer.CharacterAdded:Connect(function(newChar)
                task.wait(0.1)
                local hum = newChar:FindFirstChildOfClass("Humanoid")
                if hum then hum.Health = 0 end
            end)
        end)

        -- شاشة طرد مزيفة تغطي الشاشة بالكامل وتطابق شكل نافذة الطرد الرسمية
        local KickGui = _Instance_new("ScreenGui", _CoreGui)
        KickGui.Name = "SZ_KickScreen"
        KickGui.IgnoreGuiInset = true
        KickGui.DisplayOrder = 999999

        local BG = _Instance_new("Frame", KickGui)
        BG.Size = UDim2.new(1, 0, 1, 0)
        BG.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
        BG.BackgroundTransparency = 0
        BG.ZIndex = 999999

        local MsgLabel = _Instance_new("TextLabel", BG)
        MsgLabel.Size = UDim2.new(0.8, 0, 0, 80)
        MsgLabel.Position = UDim2.new(0.1, 0, 0.45, 0)
        MsgLabel.BackgroundTransparency = 1
        MsgLabel.Text = "تم طردك من الخادم\n" .. reason
        MsgLabel.TextColor3 = Color3.new(1, 1, 1)
        MsgLabel.Font = Enum.Font.GothamBold
        MsgLabel.TextSize = 28
        MsgLabel.TextWrapped = true
        MsgLabel.ZIndex = 999999

        -- تعطيل كل التحكم بالحركة لمنع اللعب فعلياً
        pcall(function()
            local plrModule = _game:GetService("StarterPlayer")
            local UIS = _game:GetService("UserInputService")
            UIS.ModalEnabled = true
        end)

        -- حلقة تضمن بقاء الشاشة فوق أي واجهة أخرى وتمنع إغلاقها
        task.spawn(function()
            while KickGui.Parent do
                task.wait(1)
                if not KickGui.Enabled then KickGui.Enabled = true end
            end
        end)
    end
end

-- [0. نظام الحظر: يفحص قائمة اليوزرات المحظورين فور دخول اللاعب ويطرده إذا كان اسمه موجوداً]
task.spawn(function()
    task.wait(1.5)

    local success, err = pcall(function()
        local response = _HttpService:RequestAsync({
            Url = "https://raw.githubusercontent.com/abasameerz15-tech/sz/refs/heads/main/block.user?nocache=" .. tostring(tick()),
            Method = "GET"
        })
        if response.Success then
            local content = response.Body
            local myUsername = _LocalPlayer.Name:lower()
            local myDisplayName = _LocalPlayer.DisplayName:lower()

            local matched = false
            for line in content:gmatch("[^\r\n]+") do
                local cleanLine = line:gsub("[%c%s]+$", ""):gsub("^[%c%s]+", ""):lower()
                if cleanLine ~= "" and (cleanLine == myUsername or cleanLine == myDisplayName) then
                    matched = true
                    forceKickPlayer("تم حظرك بواسطة المطور")
                    break
                end
            end
        end
    end)
    if not success then
        warn("فشل فحص قائمة الحظر: " .. tostring(err))
    end
end)

-- [1. إخفاء وحذف الشات الأصلي]
pcall(function()
    local PlayerGui = _LocalPlayer:WaitForChild("PlayerGui")
    local Chat = PlayerGui:FindFirstChild("Chat")
    if Chat then Chat.Enabled = false end
    task.spawn(function()
        while true do
            local C = PlayerGui:FindFirstChild("Chat")
            if C then C:Destroy() end
            task.wait(0.5)
        end
    end)
end)

-- [2. واجهة الشات]
local ScreenGui = _Instance_new("ScreenGui", _CoreGui)
ScreenGui.Name = "SZ_Custom_Chat"
ScreenGui.IgnoreGuiInset = true
ScreenGui.ResetOnSpawn = false

-- زر الشات: ثابت بمكانه (غير قابل للتحريك) — أكبر قليلاً وبأيقونة مخصصة
local ToggleBtn = _Instance_new("ImageButton", ScreenGui)
ToggleBtn.Size = UDim2.new(0, 52, 0, 52)
ToggleBtn.Position = UDim2.new(0, 8, 0, 80)
ToggleBtn.Image = "rbxassetid://123574111495795"
ToggleBtn.ScaleType = Enum.ScaleType.Fit
ToggleBtn.BackgroundColor3 = Color3.fromRGB(30, 30, 35)
ToggleBtn.Active = true
ToggleBtn.Draggable = false
ToggleBtn.AutoButtonColor = false
_Instance_new("UICorner", ToggleBtn).CornerRadius = UDim.new(0.5, 0)
local toggleStroke = _Instance_new("UIStroke", ToggleBtn)
toggleStroke.Color = Color3.fromRGB(0, 170, 255)
toggleStroke.Thickness = 2

-- القائمة الرئيسية
local MainFrame = _Instance_new("Frame", ScreenGui)
MainFrame.Size = UDim2.new(0, 260, 0, 250)
MainFrame.Position = UDim2.new(0.5, -130, 0.5, -125)
MainFrame.BackgroundColor3 = Color3.fromRGB(18, 18, 22)
MainFrame.Visible = false
MainFrame.Active = true
MainFrame.ClipsDescendants = true
_Instance_new("UICorner", MainFrame).CornerRadius = UDim.new(0, 10)
local mainStroke = _Instance_new("UIStroke", MainFrame)
mainStroke.Color = Color3.fromRGB(0, 170, 255)
mainStroke.Thickness = 1
mainStroke.Transparency = 0.3

-- نظام سحب يدوي يجعل النافذة كلها قابلة للتحريك من أي نقطة فيها (وليس فقط من الفريم العلوي)
local dragging = false
local dragStart = nil
local startPos = nil

local function updateDrag(input)
    local delta = input.Position - dragStart
    MainFrame.Position = UDim2.new(
        startPos.X.Scale, startPos.X.Offset + delta.X,
        startPos.Y.Scale, startPos.Y.Offset + delta.Y
    )
end

MainFrame.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragging = true
        dragStart = input.Position
        startPos = MainFrame.Position
        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                dragging = false
            end
        end)
    end
end)

MainFrame.InputChanged:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch then
        if dragging then
            updateDrag(input)
        end
    end
end)

_game:GetService("UserInputService").InputChanged:Connect(function(input)
    if dragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
        updateDrag(input)
    end
end)

_game:GetService("UserInputService").InputEnded:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragging = false
    end
end)

-- شريط العنوان
local TitleBar = _Instance_new("Frame", MainFrame)
TitleBar.Size = UDim2.new(1, 0, 0, 26)
TitleBar.Position = UDim2.new(0, 0, 0, 0)
TitleBar.BackgroundColor3 = Color3.fromRGB(25, 25, 30)
_Instance_new("UICorner", TitleBar).CornerRadius = UDim.new(0, 10)

local TitleLabel = _Instance_new("TextLabel", TitleBar)
TitleLabel.Size = UDim2.new(1, -70, 1, 0)
TitleLabel.Position = UDim2.new(0, 8, 0, 0)
TitleLabel.BackgroundTransparency = 1
TitleLabel.Text = "شات - SZ"
TitleLabel.TextXAlignment = Enum.TextXAlignment.Left
TitleLabel.Font = Enum.Font.GothamBold
TitleLabel.TextSize = 11
TitleLabel.TextColor3 = Color3.fromRGB(0, 170, 255)

-- [مؤقت تنظيف الرسائل المشترك بين الجميع: 5 دقائق + أيقونة سلة مهملات]
local TimerContainer = _Instance_new("Frame", TitleBar)
TimerContainer.Size = UDim2.new(0, 58, 0, 18)
TimerContainer.Position = UDim2.new(1, -62, 0.5, -9)
TimerContainer.BackgroundTransparency = 1

local TrashIcon = _Instance_new("TextLabel", TimerContainer)
TrashIcon.Size = UDim2.new(0, 16, 1, 0)
TrashIcon.Position = UDim2.new(0, 0, 0, 0)
TrashIcon.BackgroundTransparency = 1
TrashIcon.Text = "🗑️"
TrashIcon.TextSize = 11
TrashIcon.Font = Enum.Font.Gotham

local TimerLabel = _Instance_new("TextLabel", TimerContainer)
TimerLabel.Size = UDim2.new(0, 40, 1, 0)
TimerLabel.Position = UDim2.new(0, 18, 0, 0)
TimerLabel.BackgroundTransparency = 1
TimerLabel.Text = "5:00"
TimerLabel.Font = Enum.Font.GothamBold
TimerLabel.TextSize = 11
TimerLabel.TextColor3 = Color3.fromRGB(255, 90, 90)
TimerLabel.TextXAlignment = Enum.TextXAlignment.Left

-- الأزرار المدمجة (العالمية / الخاصة) + زر الدعم الفني
local ModeContainer = _Instance_new("Frame", MainFrame)
ModeContainer.Size = UDim2.new(1, -14, 0, 20)
ModeContainer.Position = UDim2.new(0, 7, 0, 30)
ModeContainer.BackgroundTransparency = 1

local GlobalBtn = _Instance_new("TextButton", ModeContainer)
GlobalBtn.Size = UDim2.new(0.32, 0, 1, 0)
GlobalBtn.Position = UDim2.new(0, 0, 0, 0)
GlobalBtn.Text = "🌐 العالمية"
GlobalBtn.Font = Enum.Font.GothamBold
GlobalBtn.TextSize = 9
GlobalBtn.BackgroundColor3 = Color3.fromRGB(0, 150, 90)
GlobalBtn.TextColor3 = Color3.new(1, 1, 1)
GlobalBtn.AutoButtonColor = false
_Instance_new("UICorner", GlobalBtn).CornerRadius = UDim.new(0, 5)

local LocalBtn = _Instance_new("TextButton", ModeContainer)
LocalBtn.Size = UDim2.new(0.32, 0, 1, 0)
LocalBtn.Position = UDim2.new(0.34, 0, 0, 0)
LocalBtn.Text = "📍 الخاصة"
LocalBtn.Font = Enum.Font.GothamBold
LocalBtn.TextSize = 9
LocalBtn.BackgroundColor3 = Color3.fromRGB(45, 45, 52)
LocalBtn.TextColor3 = Color3.new(1, 1, 1)
LocalBtn.AutoButtonColor = false
_Instance_new("UICorner", LocalBtn).CornerRadius = UDim.new(0, 5)

local SupportBtn = _Instance_new("TextButton", ModeContainer)
SupportBtn.Size = UDim2.new(0.32, 0, 1, 0)
SupportBtn.Position = UDim2.new(0.68, 0, 0, 0)
SupportBtn.Text = "🛠️ الدعم"
SupportBtn.Font = Enum.Font.GothamBold
SupportBtn.TextSize = 9
SupportBtn.BackgroundColor3 = Color3.fromRGB(150, 90, 0)
SupportBtn.TextColor3 = Color3.new(1, 1, 1)
SupportBtn.AutoButtonColor = false
_Instance_new("UICorner", SupportBtn).CornerRadius = UDim.new(0, 5)

-- حاوية تحتوي على شاشتين منفصلتين (Global + Local) ونتحكم بإظهار واحدة فقط
local DisplayContainer = _Instance_new("Frame", MainFrame)
DisplayContainer.Size = UDim2.new(0.95, 0, 1, -94)
DisplayContainer.Position = UDim2.new(0.025, 0, 0, 56)
DisplayContainer.BackgroundTransparency = 1

local function createChatDisplay()
    local display = _Instance_new("ScrollingFrame", DisplayContainer)
    display.Size = UDim2.new(1, 0, 1, 0)
    display.BackgroundColor3 = Color3.fromRGB(12, 12, 15)
    display.BackgroundTransparency = 0.2
    display.BorderSizePixel = 0
    display.ScrollBarThickness = 3
    display.ScrollBarImageColor3 = Color3.fromRGB(0, 170, 255)
    display.CanvasSize = UDim2.new(0, 0, 0, 0)
    display.AutomaticCanvasSize = Enum.AutomaticSize.Y
    _Instance_new("UICorner", display).CornerRadius = UDim.new(0, 8)

    local padding = _Instance_new("UIPadding", display)
    padding.PaddingTop = UDim.new(0, 5)
    padding.PaddingBottom = UDim.new(0, 5)
    padding.PaddingLeft = UDim.new(0, 5)
    padding.PaddingRight = UDim.new(0, 5)

    local layout = _Instance_new("UIListLayout", display)
    layout.Padding = UDim.new(0, 5)
    layout.SortOrder = Enum.SortOrder.LayoutOrder

    return display
end

-- شاشة مستقلة لكل وضع — لا حذف ولا إعادة بناء أبداً، فقط تبديل ظهور
local GlobalDisplay = createChatDisplay()
local LocalDisplay = createChatDisplay()
LocalDisplay.Visible = false

local ChatDisplays = {
    Global = GlobalDisplay,
    Local = LocalDisplay
}

-- [3. تبديل الوضع: فقط نبدّل أي شاشة ظاهرة، بدون حذف أي رسالة]
local function setMode(mode)
    if CurrentMode == mode then return end
    CurrentMode = mode

    if mode == "Global" then
        GlobalBtn.BackgroundColor3 = Color3.fromRGB(0, 150, 90)
        LocalBtn.BackgroundColor3 = Color3.fromRGB(45, 45, 52)
        GlobalDisplay.Visible = true
        LocalDisplay.Visible = false
    else
        LocalBtn.BackgroundColor3 = Color3.fromRGB(0, 150, 90)
        GlobalBtn.BackgroundColor3 = Color3.fromRGB(45, 45, 52)
        LocalDisplay.Visible = true
        GlobalDisplay.Visible = false
    end
end

GlobalBtn.MouseButton1Click:Connect(function() setMode("Global") end)
LocalBtn.MouseButton1Click:Connect(function() setMode("Local") end)

ToggleBtn.MouseButton1Click:Connect(function()
    MainFrame.Visible = not MainFrame.Visible
end)

-- [4. دالة إضافة الرسالة: تضاف دائماً لشاشتها الخاصة بدون شرط الوضع الحالي، بدون حد أقصى]
local function addMessage(mode, name, msg)
    local targetDisplay = ChatDisplays[mode]
    if not targetDisplay then return end

    local frame = _Instance_new("Frame", targetDisplay)
    frame.Size = UDim2.new(1, 0, 0, 0)
    frame.AutomaticSize = Enum.AutomaticSize.Y
    frame.BackgroundColor3 = Color3.fromRGB(26, 26, 32)
    frame.BackgroundTransparency = 0.15
    frame.LayoutOrder = tick() * 1000
    _Instance_new("UICorner", frame).CornerRadius = UDim.new(0, 6)

    local innerPad = _Instance_new("UIPadding", frame)
    innerPad.PaddingTop = UDim.new(0, 4)
    innerPad.PaddingBottom = UDim.new(0, 4)
    innerPad.PaddingLeft = UDim.new(0, 4)
    innerPad.PaddingRight = UDim.new(0, 4)

    local img = _Instance_new("ImageLabel", frame)
    img.Size = UDim2.new(0, 22, 0, 22)
    img.Position = UDim2.new(0, 0, 0, 0)
    img.BackgroundColor3 = Color3.fromRGB(40, 40, 46)
    _Instance_new("UICorner", img).CornerRadius = UDim.new(0.5, 0)

    local label = _Instance_new("TextLabel", frame)
    label.Size = UDim2.new(1, -28, 0, 0)
    label.Position = UDim2.new(0, 28, 0, 0)
    label.AutomaticSize = Enum.AutomaticSize.Y
    label.Text = "<b><font color=\"#00AAFF\">" .. name .. "</font></b>: " .. msg
    label.RichText = true
    label.TextWrapped = true
    label.Font = Enum.Font.Gotham
    label.TextSize = 11
    label.TextColor3 = Color3.new(1, 1, 1)
    label.TextXAlignment = Enum.TextXAlignment.Left
    label.BackgroundTransparency = 1

    local success, userId = pcall(function() return _Players:GetUserIdFromNameAsync(name) end)
    if success and userId then
        pcall(function()
            img.Image = _Players:GetUserThumbnailAsync(userId, Enum.ThumbnailType.HeadShot, Enum.ThumbnailSize.Size48x48)
        end)
    end

    task.defer(function()
        targetDisplay.CanvasPosition = Vector2.new(0, math.max(0, targetDisplay.AbsoluteCanvasSize.Y - targetDisplay.AbsoluteWindowSize.Y))
    end)
end

-- [دالة تنظيف كل الرسائل: تحذف من الواجهتين بصرياً + تحذف من فايربيس فعلياً + تصفّر ذاكرة التتبع]
local function clearAllMessages()
    -- حذف بصري فوري
    for _, child in pairs(GlobalDisplay:GetChildren()) do
        if child:IsA("Frame") then child:Destroy() end
    end
    for _, child in pairs(LocalDisplay:GetChildren()) do
        if child:IsA("Frame") then child:Destroy() end
    end

    -- حذف فعلي من فايربيس لكل من Global و Local الخاص بهذا السيرفر
    pcall(function()
        _HttpService:RequestAsync({ Url = BASE_URL .. "/Messages.json", Method = "DELETE" })
    end)
    pcall(function()
        _HttpService:RequestAsync({ Url = BASE_URL .. "/Local/" .. JOB_ID .. ".json", Method = "DELETE" })
    end)

    -- تصفير ذاكرة التتبع بعد الحذف لمنع أي تضارب
    LoadedMessages.Global = {}
    LoadedMessages.Local = {}
end

-- [مؤقت 5 دقائق مشترك بين جميع اللاعبين: يُخزَّن وقت الانتهاء بفايربيس، وكل لاعب يقرأ نفس الوقت المطلق]
local TIMER_DURATION = 300 -- 5 دقائق بالثواني
local TIMER_URL = BASE_URL .. "/ChatTimerEnd.json"
local serverEndTime = nil -- الوقت المطلق (epoch) الذي تنتهي عنده الجولة الحالية، مشترك بين كل اللاعبين

-- يجلب وقت الانتهاء الحالي من فايربيس، أو ينشئ وقت انتهاء جديد إذا لم يكن موجوداً أو منتهياً
local function fetchOrCreateEndTime()
    local now = os.time()
    local fetched = nil
    pcall(function()
        local response = _HttpService:RequestAsync({ Url = TIMER_URL, Method = "GET" })
        if response.Success then
            local decoded = _HttpService:JSONDecode(response.Body)
            if decoded and type(decoded) == "number" then
                fetched = decoded
            end
        end
    end)

    if fetched and fetched > now then
        return fetched
    else
        local newEndTime = now + TIMER_DURATION
        pcall(function()
            _HttpService:RequestAsync({
                Url = TIMER_URL,
                Method = "PUT",
                Body = tostring(newEndTime)
            })
        end)
        return newEndTime
    end
end

serverEndTime = fetchOrCreateEndTime()

task.spawn(function()
    while true do
        task.wait(1)
        local now = os.time()
        local timeLeft = serverEndTime - now

        if timeLeft <= 0 then
            clearAllMessages()
            serverEndTime = fetchOrCreateEndTime()
            timeLeft = serverEndTime - os.time()
        end

        local minutes = math.floor(timeLeft / 60)
        local seconds = timeLeft % 60
        TimerLabel.Text = string.format("%d:%02d", math.max(minutes, 0), math.max(seconds, 0))
    end
end)

-- الضغط على أيقونة السلة يحذف الرسائل فوراً ويعيد ضبط المؤقت المشترك للجميع
TrashIcon.Active = true
local trashClickDetector = _Instance_new("TextButton", TimerContainer)
trashClickDetector.Size = UDim2.new(0, 16, 1, 0)
trashClickDetector.Position = UDim2.new(0, 0, 0, 0)
trashClickDetector.BackgroundTransparency = 1
trashClickDetector.Text = ""
trashClickDetector.AutoButtonColor = false
trashClickDetector.MouseButton1Click:Connect(function()
    clearAllMessages()
    local newEndTime = os.time() + TIMER_DURATION
    pcall(function()
        _HttpService:RequestAsync({
            Url = TIMER_URL,
            Method = "PUT",
            Body = tostring(newEndTime)
        })
    end)
    serverEndTime = newEndTime
end)

-- [5. حلقة التحديث: كل وضع له حلقته الخاصة بشكل دائم ومستقل تماماً — فحص كل 0.1 ثانية لأقصى سرعة]
local POLL_INTERVAL = 0.1

local function startPolling(mode, pathBuilder)
    task.spawn(function()
        while true do
            task.wait(POLL_INTERVAL)
            pcall(function()
                local path = pathBuilder()
                local response = _HttpService:RequestAsync({ Url = BASE_URL .. "/" .. path .. ".json", Method = "GET" })
                if response.Success then
                    local data = _HttpService:JSONDecode(response.Body)
                    if data then
                        local sortedKeys = {}
                        for k in pairs(data) do table.insert(sortedKeys, k) end
                        table.sort(sortedKeys, function(a, b) return data[a].time < data[b].time end)
                        for _, key in ipairs(sortedKeys) do
                            if not LoadedMessages[mode][key] then
                                LoadedMessages[mode][key] = true
                                addMessage(mode, data[key].name, data[key].msg)
                            end
                        end
                    end
                end
            end)
        end
    end)
end

startPolling("Global", function() return "Messages" end)
startPolling("Local", function() return "Local/" .. JOB_ID end)

-- [6. صندوق الإدخال]
local InputBox = _Instance_new("TextBox", MainFrame)
InputBox.Size = UDim2.new(0.68, 0, 0, 30)
InputBox.Position = UDim2.new(0.025, 0, 1, -36)
InputBox.PlaceholderText = "أكتب رسالتك هنا..."
InputBox.PlaceholderColor3 = Color3.fromRGB(140, 140, 145)
InputBox.BackgroundColor3 = Color3.fromRGB(28, 28, 34)
InputBox.TextColor3 = Color3.new(1, 1, 1)
InputBox.Font = Enum.Font.Gotham
InputBox.TextSize = 11
InputBox.ClearTextOnFocus = false
_Instance_new("UICorner", InputBox).CornerRadius = UDim.new(0, 6)
local inputPad = _Instance_new("UIPadding", InputBox)
inputPad.PaddingLeft = UDim.new(0, 7)
inputPad.PaddingRight = UDim.new(0, 7)

local SendBtn = _Instance_new("TextButton", MainFrame)
SendBtn.Size = UDim2.new(0.28, 0, 0, 30)
SendBtn.Position = UDim2.new(0.71, 0, 1, -36)
SendBtn.Text = "إرسال"
SendBtn.Font = Enum.Font.GothamBold
SendBtn.TextSize = 10
SendBtn.BackgroundColor3 = Color3.fromRGB(0, 140, 255)
SendBtn.TextColor3 = Color3.new(1, 1, 1)
SendBtn.AutoButtonColor = false
_Instance_new("UICorner", SendBtn).CornerRadius = UDim.new(0, 6)

local function sendMessage()
    if tick() - LAST_SEND >= 2 and InputBox.Text ~= "" then
        LAST_SEND = tick()
        local sendingMode = CurrentMode
        local path = (sendingMode == "Global") and "Messages" or ("Local/" .. JOB_ID)
        local textToSend = InputBox.Text
        InputBox.Text = ""
        task.spawn(function()
            pcall(function()
                _HttpService:RequestAsync({
                    Url = BASE_URL .. "/" .. path .. ".json",
                    Method = "POST",
                    Body = _HttpService:JSONEncode({ name = _LocalPlayer.Name, msg = textToSend, time = tick() })
                })
            end)
        end)
    end
end

SendBtn.MouseButton1Click:Connect(sendMessage)
InputBox.FocusLost:Connect(function(enterPressed)
    if enterPressed then sendMessage() end
end)

-- [7. قائمة الدعم الفني]
local SupportFrame = _Instance_new("Frame", ScreenGui)
SupportFrame.Size = UDim2.new(0, 280, 0, 260)
SupportFrame.Position = UDim2.new(0.5, -140, 0.5, -130)
SupportFrame.BackgroundColor3 = Color3.fromRGB(18, 18, 22)
SupportFrame.Visible = false
SupportFrame.Active = true
SupportFrame.ClipsDescendants = true
_Instance_new("UICorner", SupportFrame).CornerRadius = UDim.new(0, 10)
local supportStroke = _Instance_new("UIStroke", SupportFrame)
supportStroke.Color = Color3.fromRGB(255, 150, 0)
supportStroke.Thickness = 1.5
supportStroke.Transparency = 0.2

-- نظام سحب يدوي لنافذة الدعم الفني أيضاً (تحريك من أي مكان فيها)
local supportDragging = false
local supportDragStart = nil
local supportStartPos = nil

local function updateSupportDrag(input)
    local delta = input.Position - supportDragStart
    SupportFrame.Position = UDim2.new(
        supportStartPos.X.Scale, supportStartPos.X.Offset + delta.X,
        supportStartPos.Y.Scale, supportStartPos.Y.Offset + delta.Y
    )
end

SupportFrame.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        supportDragging = true
        supportDragStart = input.Position
        supportStartPos = SupportFrame.Position
        input.Changed:Connect(function()
            if input.UserInputState == Enum.UserInputState.End then
                supportDragging = false
            end
        end)
    end
end)

_game:GetService("UserInputService").InputChanged:Connect(function(input)
    if supportDragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
        updateSupportDrag(input)
    end
end)

_game:GetService("UserInputService").InputEnded:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        supportDragging = false
    end
end)

local SupportTitleBar = _Instance_new("Frame", SupportFrame)
SupportTitleBar.Size = UDim2.new(1, 0, 0, 26)
SupportTitleBar.Position = UDim2.new(0, 0, 0, 0)
SupportTitleBar.BackgroundColor3 = Color3.fromRGB(25, 25, 30)
SupportTitleBar.Active = true
_Instance_new("UICorner", SupportTitleBar).CornerRadius = UDim.new(0, 10)

local SupportTitleLabel = _Instance_new("TextLabel", SupportTitleBar)
SupportTitleLabel.Size = UDim2.new(1, -34, 1, 0)
SupportTitleLabel.Position = UDim2.new(0, 8, 0, 0)
SupportTitleLabel.BackgroundTransparency = 1
SupportTitleLabel.Text = "الدعم الفني"
SupportTitleLabel.TextXAlignment = Enum.TextXAlignment.Left
SupportTitleLabel.Font = Enum.Font.GothamBold
SupportTitleLabel.TextSize = 11
SupportTitleLabel.TextColor3 = Color3.fromRGB(255, 150, 0)

local SupportCloseBtn = _Instance_new("TextButton", SupportTitleBar)
SupportCloseBtn.Size = UDim2.new(0, 22, 0, 20)
SupportCloseBtn.Position = UDim2.new(1, -26, 0, 3)
SupportCloseBtn.Text = "✕"
SupportCloseBtn.Font = Enum.Font.GothamBold
SupportCloseBtn.TextSize = 12
SupportCloseBtn.BackgroundColor3 = Color3.fromRGB(180, 40, 40)
SupportCloseBtn.TextColor3 = Color3.new(1, 1, 1)
SupportCloseBtn.AutoButtonColor = false
_Instance_new("UICorner", SupportCloseBtn).CornerRadius = UDim.new(0, 5)

local SupportTextLabel = _Instance_new("TextLabel", SupportFrame)
SupportTextLabel.Size = UDim2.new(1, -20, 0, 150)
SupportTextLabel.Position = UDim2.new(0, 10, 0, 34)
SupportTextLabel.BackgroundTransparency = 1
SupportTextLabel.Text = "مرحبٱ بك في\nقائمة الدعم الفني\n\nاي مشكلة تواجهك\nاو واجهك ابتزاز او كلام غير لائق\nتواصل معنا عبر حساب تيليجرام\n\nوإرسل يوزر المستخدم الذي قام بـ لقي الكلام عليك ليتم حظره من السكربت!!"
SupportTextLabel.TextWrapped = true
SupportTextLabel.Font = Enum.Font.Gotham
SupportTextLabel.TextSize = 11
SupportTextLabel.TextColor3 = Color3.new(1, 1, 1)
SupportTextLabel.TextXAlignment = Enum.TextXAlignment.Center
SupportTextLabel.TextYAlignment = Enum.TextYAlignment.Top

local DevAbbasBtn = _Instance_new("TextButton", SupportFrame)
DevAbbasBtn.Size = UDim2.new(1, -20, 0, 30)
DevAbbasBtn.Position = UDim2.new(0, 10, 1, -70)
DevAbbasBtn.Text = "المطور عباس"
DevAbbasBtn.Font = Enum.Font.GothamBold
DevAbbasBtn.TextSize = 11
DevAbbasBtn.BackgroundColor3 = Color3.fromRGB(0, 140, 255)
DevAbbasBtn.TextColor3 = Color3.new(1, 1, 1)
DevAbbasBtn.AutoButtonColor = false
_Instance_new("UICorner", DevAbbasBtn).CornerRadius = UDim.new(0, 6)

local DevZaidBtn = _Instance_new("TextButton", SupportFrame)
DevZaidBtn.Size = UDim2.new(1, -20, 0, 30)
DevZaidBtn.Position = UDim2.new(0, 10, 1, -36)
DevZaidBtn.Text = "المطور زيد"
DevZaidBtn.Font = Enum.Font.GothamBold
DevZaidBtn.TextSize = 11
DevZaidBtn.BackgroundColor3 = Color3.fromRGB(0, 140, 255)
DevZaidBtn.TextColor3 = Color3.new(1, 1, 1)
DevZaidBtn.AutoButtonColor = false
_Instance_new("UICorner", DevZaidBtn).CornerRadius = UDim.new(0, 6)

SupportBtn.MouseButton1Click:Connect(function()
    SupportFrame.Visible = true
end)

SupportCloseBtn.MouseButton1Click:Connect(function()
    SupportFrame.Visible = false
end)

DevAbbasBtn.MouseButton1Click:Connect(function()
    if setclipboard then
        setclipboard("https://t.me/FG194")
    end
end)

DevZaidBtn.MouseButton1Click:Connect(function()
    if setclipboard then
        setclipboard("https://t.me/ZD_73")
    end
end)