import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { Upload, Youtube, FileText, ArrowRight, Sparkles, Globe, Type, Settings, BookOpen, Clock, Target, Brain, Mic } from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import CoursePreview from "./CoursePreview";
import { supabase } from "@/integrations/supabase/client";

const UploadSection = () => {
  const [youtubeUrl, setYoutubeUrl] = useState("");
  const [webUrl, setWebUrl] = useState("");
  const [textContent, setTextContent] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [showCoursePreview, setShowCoursePreview] = useState(false);
  const [courseTitle, setCourseTitle] = useState("");
  const [sourceType, setSourceType] = useState<"youtube" | "pdf" | "text" | "web" | "audio">("youtube");
  const [inputContent, setInputContent] = useState("");
  const [generatedCourseContent, setGeneratedCourseContent] = useState<any>(null);
  
  // Advanced settings
  const [difficulty, setDifficulty] = useState("intermediate");
  const [courseLength, setCourseLength] = useState("medium");
  const [learningStyle, setLearningStyle] = useState("balanced");
  const [language, setLanguage] = useState("english");
  const [quizQuestions, setQuizQuestions] = useState([10]);
  const [flashcardCount, setFlashcardCount] = useState([15]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  const { toast } = useToast();

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(e.type === "dragenter" || e.type === "dragover");
  };

  const generateCourseContent = async (type: "youtube" | "pdf" | "text" | "web" | "audio", content: string, title: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('generate-course-content', {
        body: {
          sourceType: type,
          content: content,
          title: title,
          difficulty,
          courseLength,
          learningStyle,
          language,
          quizQuestions: quizQuestions[0],
          flashcardCount: flashcardCount[0]
        }
      });

      if (error) throw error;

      if (data.success) {
        setGeneratedCourseContent(data.courseContent);
        return data.courseContent;
      } else {
        throw new Error(data.error || 'Failed to generate content');
      }
    } catch (error) {
      console.error('Course generation error:', error);
      toast({
        title: "Generation Failed",
        description: "Failed to generate AI content. Using sample content instead.",
        variant: "destructive",
      });
      return null;
    }
  };

  const handleYouTubeSubmit = async () => {
    if (!youtubeUrl.trim()) {
      toast({
        title: "URL Required",
        description: "Please enter a YouTube URL to continue.",
        variant: "destructive",
      });
      return;
    }

    setIsProcessing(true);
    toast({
      title: "AI Processing Started!",
      description: "Analyzing your YouTube video and generating comprehensive course content...",
    });

    setSourceType("youtube");
    setInputContent(youtubeUrl);
    
    // Generate dynamic title based on URL
    const generateTitleFromUrl = (url: string) => {
      const urlObj = new URL(url);
      if (urlObj.hostname.includes('youtube')) {
        const videoId = urlObj.searchParams.get('v');
        return `Advanced Course from YouTube Video (${videoId?.substring(0, 8) || 'Video'})`;
      }
      return "Advanced Course from YouTube Video";
    };
    
    const title = generateTitleFromUrl(youtubeUrl);
    setCourseTitle(title);

    // Generate real AI content
    const content = await generateCourseContent("youtube", youtubeUrl, title);
    
    setTimeout(() => {
      setIsProcessing(false);
      setShowCoursePreview(true);
      toast({
        title: "AI Course Generated Successfully!",
        description: "Your comprehensive micro-course is ready with detailed notes, challenging quizzes, and AI tutor.",
      });
      // Scroll to preview
      setTimeout(() => {
        document.getElementById('course-preview')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }, 2000);
  };

  const handleFileUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    setIsProcessing(true);
    toast({
      title: "AI Processing Started!",
      description: `Analyzing ${files.length} PDF file(s) and generating comprehensive course content...`,
    });

    setSourceType("pdf");
    const fileNames = Array.from(files).map(f => f.name).join(", ");
    setInputContent(fileNames);
    
    // Generate dynamic title based on file names
    const generateTitleFromFiles = (fileList: FileList) => {
      const fileNames = Array.from(fileList).map(f => f.name.replace('.pdf', ''));
      if (fileList.length === 1) {
        return `Advanced Course: ${fileNames[0]}`;
      } else {
        return `Comprehensive Multi-PDF Course (${fileList.length} documents)`;
      }
    };
    
    const title = generateTitleFromFiles(files);
    setCourseTitle(title);

    // Generate real AI content
    const content = await generateCourseContent("pdf", fileNames, title);

    setTimeout(() => {
      setIsProcessing(false);
      setShowCoursePreview(true);
      toast({
        title: "AI Course Generated Successfully!",
        description: "Your PDF content has been transformed into a comprehensive interactive course.",
      });
      // Scroll to preview
      setTimeout(() => {
        document.getElementById('course-preview')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }, 2000);
  };

  const handleWebUrlSubmit = async () => {
    if (!webUrl.trim()) {
      toast({
        title: "URL Required",
        description: "Please enter a web URL to continue.",
        variant: "destructive",
      });
      return;
    }

    // Validate URL format
    try {
      new URL(webUrl);
    } catch {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL (e.g., https://example.com/article)",
        variant: "destructive",
      });
      return;
    }

    setIsProcessing(true);
    toast({
      title: "AI Processing Started!",
      description: "Analyzing web content and generating comprehensive course...",
    });

    setSourceType("web");
    setInputContent(webUrl);
    const title = `Web Article Course: ${new URL(webUrl).hostname.replace('www.', '')}`;
    setCourseTitle(title);

    const content = await generateCourseContent("web", webUrl, title);
    
    setTimeout(() => {
      setIsProcessing(false);
      setShowCoursePreview(true);
      setWebUrl(""); // Clear the input after successful submission
      toast({
        title: "AI Course Generated Successfully!",
        description: "Your web content has been transformed into an interactive course.",
      });
      setTimeout(() => {
        document.getElementById('course-preview')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }, 2000);
  };

  const handleTextSubmit = async () => {
    if (!textContent.trim()) {
      toast({
        title: "Content Required",
        description: "Please enter some text content to continue.",
        variant: "destructive",
      });
      return;
    }

    if (textContent.trim().length < 50) {
      toast({
        title: "Content Too Short",
        description: "Please enter at least 50 characters of content for better course generation.",
        variant: "destructive",
      });
      return;
    }

    setIsProcessing(true);
    toast({
      title: "AI Processing Started!",
      description: "Processing your text content and generating comprehensive course...",
    });

    setSourceType("text");
    setInputContent(textContent);
    const title = courseTitle.trim() || `Custom Course: ${textContent.substring(0, 30)}...`;
    setCourseTitle(title);

    const content = await generateCourseContent("text", textContent, title);
    
    setTimeout(() => {
      setIsProcessing(false);
      setShowCoursePreview(true);
      setTextContent(""); // Clear the input after successful submission
      setCourseTitle(""); // Clear the title input
      toast({
        title: "AI Course Generated Successfully!",
        description: "Your text has been transformed into an interactive course.",
      });
      setTimeout(() => {
        document.getElementById('course-preview')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }, 2000);
  };

  const handleAudioUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    setIsProcessing(true);
    toast({
      title: "AI Processing Started!",
      description: "Transcribing audio and generating comprehensive course content...",
    });

    setSourceType("audio");
    const fileNames = Array.from(files).map(f => f.name).join(", ");
    setInputContent(fileNames);
    const title = `Audio Course: ${Array.from(files)[0].name.replace(/\.[^/.]+$/, "")}`;
    setCourseTitle(title);

    const content = await generateCourseContent("audio", fileNames, title);

    setTimeout(() => {
      setIsProcessing(false);
      setShowCoursePreview(true);
      toast({
        title: "AI Course Generated Successfully!",
        description: "Your audio has been transcribed and transformed into an interactive course.",
      });
      setTimeout(() => {
        document.getElementById('course-preview')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }, 2000);
  };

  return (
    <section id="upload-section" className="py-20 bg-muted/30">
      <div className="max-w-4xl mx-auto px-6">
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold mb-4">
            Start Your Course
            <span className="bg-gradient-primary bg-clip-text text-transparent"> Creation</span>
          </h2>
          <p className="text-xl text-muted-foreground">
            Upload your content and let AI transform it into an engaging learning experience
          </p>
        </div>

        <Card className="bg-gradient-card shadow-elegant border-0">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-2xl">
              <Sparkles className="w-6 h-6 text-primary" />
              Content Upload
            </CardTitle>
          </CardHeader>
          <CardContent>
            {/* Advanced Settings Toggle */}
            <div className="mb-6">
              <Button 
                variant="outline" 
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="mb-4"
              >
                <Settings className="w-4 h-4 mr-2" />
                {showAdvanced ? "Hide" : "Show"} Advanced Settings
              </Button>
              
              {showAdvanced && (
                <Card className="p-4 space-y-4 bg-muted/20">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Difficulty Level</Label>
                      <Select value={difficulty} onValueChange={setDifficulty}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="beginner">Beginner</SelectItem>
                          <SelectItem value="intermediate">Intermediate</SelectItem>
                          <SelectItem value="advanced">Advanced</SelectItem>
                          <SelectItem value="expert">Expert</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Course Length</Label>
                      <Select value={courseLength} onValueChange={setCourseLength}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="short">Short (15-30 min)</SelectItem>
                          <SelectItem value="medium">Medium (45-60 min)</SelectItem>
                          <SelectItem value="long">Long (90+ min)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Learning Style</Label>
                      <Select value={learningStyle} onValueChange={setLearningStyle}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="visual">Visual</SelectItem>
                          <SelectItem value="auditory">Auditory</SelectItem>
                          <SelectItem value="kinesthetic">Kinesthetic</SelectItem>
                          <SelectItem value="balanced">Balanced</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Language</Label>
                      <Select value={language} onValueChange={setLanguage}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="english">English</SelectItem>
                          <SelectItem value="spanish">Spanish</SelectItem>
                          <SelectItem value="french">French</SelectItem>
                          <SelectItem value="german">German</SelectItem>
                          <SelectItem value="chinese">Chinese</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-3">
                      <Label>Quiz Questions: {quizQuestions[0]}</Label>
                      <Slider
                        value={quizQuestions}
                        onValueChange={setQuizQuestions}
                        max={20}
                        min={5}
                        step={1}
                        className="w-full"
                      />
                    </div>
                    
                    <div className="space-y-3">
                      <Label>Flashcards: {flashcardCount[0]}</Label>
                      <Slider
                        value={flashcardCount}
                        onValueChange={setFlashcardCount}
                        max={30}
                        min={10}
                        step={5}
                        className="w-full"
                      />
                    </div>
                  </div>
                </Card>
              )}
            </div>

            <Tabs defaultValue="youtube" className="w-full">
              <TabsList className="grid w-full grid-cols-5 mb-8">
                <TabsTrigger value="youtube" className="flex items-center gap-2">
                  <Youtube className="w-4 h-4" />
                  YouTube
                </TabsTrigger>
                <TabsTrigger value="pdf" className="flex items-center gap-2">
                  <FileText className="w-4 h-4" />
                  PDF
                </TabsTrigger>
                <TabsTrigger value="web" className="flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  Web URL
                </TabsTrigger>
                <TabsTrigger value="text" className="flex items-center gap-2">
                  <Type className="w-4 h-4" />
                  Text
                </TabsTrigger>
                <TabsTrigger value="audio" className="flex items-center gap-2">
                  <Mic className="w-4 h-4" />
                  Audio
                </TabsTrigger>
              </TabsList>

              <TabsContent value="youtube" className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="youtube-url" className="text-base font-medium">
                    YouTube Video URL
                  </Label>
                  <div className="flex gap-3">
                    <Input
                      id="youtube-url"
                      placeholder="https://youtube.com/watch?v=..."
                      value={youtubeUrl}
                      onChange={(e) => setYoutubeUrl(e.target.value)}
                      className="text-base h-12"
                    />
                    <Button 
                      variant="hero" 
                      size="lg" 
                      className="px-6"
                      onClick={handleYouTubeSubmit}
                      disabled={isProcessing}
                    >
                      {isProcessing ? "Generating with AI..." : "Generate Course"}
                      <ArrowRight className="w-4 h-4" />
                    </Button>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Paste any public YouTube video URL to generate a complete course
                  </p>
                </div>

                {/* YouTube preview area */}
                <div className="border-2 border-dashed border-muted-foreground/20 rounded-lg p-8 bg-muted/10">
                  <div className="text-center">
                    <Youtube className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
                    <p className="text-muted-foreground">
                      Video preview will appear here once you paste a URL
                    </p>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="pdf" className="space-y-6">
                <div
                  className={`border-2 border-dashed rounded-lg p-12 text-center transition-all ${
                    isDragging
                      ? "border-primary bg-primary/5 scale-105"
                      : "border-muted-foreground/20 hover:border-primary/50"
                  }`}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={(e) => {
                    handleDrag(e);
                    const files = e.dataTransfer.files;
                    handleFileUpload(files);
                  }}
                >
                  <Upload className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
                  <h3 className="text-xl font-semibold mb-2">
                    Drop your PDF files here
                  </h3>
                  <p className="text-muted-foreground mb-4">
                    Or click to browse and select files
                  </p>
                  <Button 
                    variant="outline" 
                    size="lg"
                    onClick={() => {
                      const input = document.createElement('input');
                      input.type = 'file';
                      input.accept = '.pdf';
                      input.multiple = true;
                      input.onchange = (e) => {
                        const target = e.target as HTMLInputElement;
                        handleFileUpload(target.files);
                      };
                      input.click();
                    }}
                  >
                    Choose Files
                  </Button>
                  <p className="text-sm text-muted-foreground mt-4">
                    Supports PDF files up to 50MB. Multiple files allowed.
                  </p>
                </div>

                <Button 
                  variant="hero" 
                  size="lg" 
                  className="w-full"
                  disabled={isProcessing}
                  onClick={() => {
                    const input = document.createElement('input');
                    input.type = 'file';
                    input.accept = '.pdf';
                    input.multiple = true;
                    input.onchange = (e) => {
                      const target = e.target as HTMLInputElement;
                      handleFileUpload(target.files);
                    };
                    input.click();
                  }}
                >
                  {isProcessing ? "Generating with AI..." : "Generate Course from PDFs"}
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </TabsContent>

              <TabsContent value="web" className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="web-url" className="text-base font-medium">
                    Article or Blog URL
                  </Label>
                  <div className="flex gap-3">
                    <Input
                      id="web-url"
                      placeholder="https://example.com/article..."
                      value={webUrl}
                      onChange={(e) => setWebUrl(e.target.value)}
                      className="text-base h-12"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          handleWebUrlSubmit();
                        }
                      }}
                    />
                    <Button 
                      variant="hero" 
                      size="lg" 
                      className="px-6"
                      onClick={handleWebUrlSubmit}
                      disabled={isProcessing}
                    >
                      {isProcessing ? "Generating..." : "Generate Course"}
                      <ArrowRight className="w-4 h-4" />
                    </Button>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Transform any article, blog post, or webpage into a structured course
                  </p>
                </div>

                <div className="border-2 border-dashed border-muted-foreground/20 rounded-lg p-8 bg-muted/10">
                  <div className="text-center">
                    <Globe className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
                    <p className="text-muted-foreground">
                      Supports articles, blog posts, documentation, and educational content
                    </p>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="text" className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="course-title" className="text-base font-medium">
                    Course Title (Optional)
                  </Label>
                  <Input
                    id="course-title"
                    placeholder="Enter a custom title for your course..."
                    value={courseTitle}
                    onChange={(e) => setCourseTitle(e.target.value)}
                    className="text-base h-12"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        document.getElementById('text-content')?.focus();
                      }
                    }}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="text-content" className="text-base font-medium">
                    Your Content
                  </Label>
                  <Textarea
                    id="text-content"
                    placeholder="Paste or type your content here... (lectures, notes, research papers, etc.)"
                    value={textContent}
                    onChange={(e) => setTextContent(e.target.value)}
                    className="min-h-40 text-base"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && e.ctrlKey) {
                        handleTextSubmit();
                      }
                    }}
                  />
                  <p className="text-sm text-muted-foreground">
                    Transform any text content into a comprehensive learning experience (Ctrl+Enter to submit)
                  </p>
                </div>

                <Button 
                  variant="hero" 
                  size="lg" 
                  className="w-full"
                  onClick={handleTextSubmit}
                  disabled={isProcessing || !textContent.trim()}
                >
                  {isProcessing ? "Generating with AI..." : "Generate Course from Text"}
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </TabsContent>

              <TabsContent value="audio" className="space-y-6">
                <div
                  className={`border-2 border-dashed rounded-lg p-12 text-center transition-all ${
                    isDragging
                      ? "border-primary bg-primary/5 scale-105"
                      : "border-muted-foreground/20 hover:border-primary/50"
                  }`}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={(e) => {
                    handleDrag(e);
                    const files = e.dataTransfer.files;
                    handleAudioUpload(files);
                  }}
                >
                  <Mic className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
                  <h3 className="text-xl font-semibold mb-2">
                    Drop your audio files here
                  </h3>
                  <p className="text-muted-foreground mb-4">
                    Podcasts, lectures, interviews, or any audio content
                  </p>
                  <Button 
                    variant="outline" 
                    size="lg"
                    onClick={() => {
                      const input = document.createElement('input');
                      input.type = 'file';
                      input.accept = 'audio/*';
                      input.multiple = true;
                      input.onchange = (e) => {
                        const target = e.target as HTMLInputElement;
                        handleAudioUpload(target.files);
                      };
                      input.click();
                    }}
                  >
                    Choose Audio Files
                  </Button>
                  <p className="text-sm text-muted-foreground mt-4">
                    Supports MP3, WAV, M4A, and other audio formats up to 100MB
                  </p>
                </div>

                <div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <Brain className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-blue-900 dark:text-blue-100">AI Audio Processing</h4>
                      <p className="text-sm text-blue-700 dark:text-blue-300">
                        Our AI will transcribe your audio, extract key concepts, and create interactive learning materials
                      </p>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* Enhanced Processing Preview */}
        <Card className="mt-8 border-primary/20 bg-gradient-to-r from-primary/5 to-secondary/5">
          <CardContent className="pt-6">
            <div className="grid md:grid-cols-3 gap-6">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-gradient-primary rounded-full flex items-center justify-center">
                  <BookOpen className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h4 className="font-semibold">Smart Notes</h4>
                  <p className="text-sm text-muted-foreground">AI-generated structured content</p>
                </div>
              </div>
              
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-gradient-secondary rounded-full flex items-center justify-center">
                  <Target className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h4 className="font-semibold">Interactive Quizzes</h4>
                  <p className="text-sm text-muted-foreground">Adaptive difficulty levels</p>
                </div>
              </div>
              
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-gradient-primary rounded-full flex items-center justify-center">
                  <Brain className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h4 className="font-semibold">AI Tutor</h4>
                  <p className="text-sm text-muted-foreground">Personalized learning assistant</p>
                </div>
              </div>
            </div>
            
            <div className="mt-6 flex flex-wrap gap-2">
              <Badge variant="secondary" className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                Estimated: {courseLength === 'short' ? '15-30 min' : courseLength === 'medium' ? '45-60 min' : '90+ min'}
              </Badge>
              <Badge variant="outline">
                Difficulty: {difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}
              </Badge>
              <Badge variant="outline">
                {quizQuestions[0]} Quiz Questions
              </Badge>
              <Badge variant="outline">
                {flashcardCount[0]} Flashcards
              </Badge>
            </div>
          </CardContent>
        </Card>

        <div id="course-preview">
          <CoursePreview 
            isVisible={showCoursePreview}
            courseTitle={courseTitle}
            sourceType={sourceType}
            inputContent={inputContent}
            generatedContent={generatedCourseContent}
          />
        </div>
      </div>
    </section>
  );
};

export default UploadSection;